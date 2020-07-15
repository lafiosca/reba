import { lambda, LambdaEvent } from 'nice-lambda';
import { S3, SES } from 'aws-sdk';

import config from './config';

const emailBucket = process.env.S3BucketEmail ?? '';
const emailPrefix = process.env.S3PrefixEmail ?? '';

const excludeHeaderPattern = /^(?:Return-Path|Sender|DKIM-Signature)$/i;
const allowDuplicateHeaderPatten = /^(?:Received)$/i;

const s3Client = new S3();
const sesClient = new SES();

interface SESRecordMail {
	timestamp: string;
	source: string;
	messageId: string;
	destination: string[];
	headersTruncated: boolean;
	headers: {
		name: string;
		value: string;
	}[];
	commonHeaders: {
		returnPath: string;
		from: string[];
		date: string;
		to: string[];
		messageId: string;
		subject: string;
	};
}

/**
 * Some values seen in the verdict fields include:
 *   PASS
 *   FAIL
 *   GRAY
 *   PROCESSING_FAILED
 */
interface SESRecordReceipt {
	timestamp: string;
	processingTimeMillis: number;
	recipients: string[];
	spamVerdict: {
		status: string;
	};
	virusVerdict: {
		status: string;
	};
	spfVerdict: {
		status: string;
	};
	dkimVerdict: {
		status: string;
	};
	dmarcVerdict: {
		status: string;
	};
	action: {
		type: 'Lambda';
		functionArn: string;
		invocationType: string;
	};
}

interface SESRecord {
	eventSource: 'aws:ses';
	eventVersion: '1.0';
	ses: {
		mail: SESRecordMail;
		receipt: SESRecordReceipt;
	};
}

/** Does a semi-thorough validation of Lambda event to ensure it looks like what we expect from SES */
const validateSesEvent = (event: LambdaEvent): SESRecord => {
	if (!event) {
		throw new Error('Missing event');
	}

	if (typeof event !== 'object') {
		throw new Error('Non-object event');
	}

	const { Records: records } = event;

	if (!records) {
		throw new Error('Event is missing Records array');
	}

	if (!Array.isArray(records)) {
		throw new Error('Event has non-array Records field');
	}

	if (records.length !== 1) {
		throw new Error(`Event Records array has length ${records.length}; expected 1`);
	}

	const record = records[0];

	if (!record) {
		throw new Error('Missing record');
	}

	if (typeof record !== 'object') {
		throw new Error('Non-object record');
	}

	const { eventSource, eventVersion, ses } = record;

	if (eventSource !== 'aws:ses') {
		throw new Error(`Record has eventSource '${eventSource}'; expected 'aws:ses'`);
	}

	if (eventVersion !== '1.0') {
		throw new Error(`Record has eventVersion '${eventVersion}'; expected '1.0'`);
	}

	if (!ses) {
		throw new Error('Record is missing ses field');
	}

	if (typeof ses !== 'object') {
		throw new Error('Record has non-object ses field');
	}

	const { mail, receipt } = ses;

	if (!mail) {
		throw new Error('Record ses data is missing mail field');
	}

	if (typeof mail !== 'object') {
		throw new Error('Record ses data has non-object mail field');
	}

	if (!receipt) {
		throw new Error('Record ses data is missing receipt field');
	}

	if (typeof receipt !== 'object') {
		throw new Error('Record ses data has non-object receipt field');
	}

	return record;
};

/** Parses an SES record for forwarding */
const parseRecord = (record: SESRecord): [SESRecordMail, string[]] => {
	console.log('Parsing SES record');

	const { mail, receipt: { recipients } } = record.ses;

	if (!recipients || !Array.isArray(recipients) || recipients.length === 0) {
		throw new Error('Record did not contain recipients');
	}

	return [mail, recipients];
};

/** Process alias forwarding rules for original recipients */
const processAliases = (origRecipients: string[]): [string[], string] => {
	console.log(`Processing aliases for original recipients: ${JSON.stringify(origRecipients, null, 2)}`);
	const { aliases } = config;
	let firstOrigRecipient = '';
	const newRecipients: string[] = [];
	origRecipients.forEach((origRecipient) => {
		let matched = false;
		for (let i = 0; !matched && i < aliases.length; i += 1) {
			const { pattern, rejectPattern, recipients: aliasRecipients } = aliases[i];
			// If the recipient matches this alias rule pattern
			if (origRecipient.match(pattern)) {
				// We've matched a rule
				matched = true;
				// If the recipient matches the rule's reject pattern
				if (rejectPattern && origRecipient.match(rejectPattern)) {
					console.log(`Recipient '${origRecipient}' matched alias rule #${i}'s reject pattern`);
				} else {
					// Keep track of the first original recipient that we processed a match for
					firstOrigRecipient = firstOrigRecipient || origRecipient;
					// Add all alias recipients, omitting duplicates
					aliasRecipients.forEach((aliasRecipient) => {
						if (!newRecipients.includes(aliasRecipient)) {
							newRecipients.push(aliasRecipient);
						}
					});
				}
			}
		}
	});
	return [newRecipients, firstOrigRecipient];
};

const buildS3Params = (mail: SESRecordMail): S3.GetObjectRequest => ({
	Bucket: emailBucket,
	Key: `${emailPrefix}${mail.messageId}`,
});

const buildS3Url = (params: S3.GetObjectRequest) => (
	`s3://${params.Bucket}/${params.Key}`
);

/** Fetch mail message body from S3, or undefined if error */
const fetchMessage = async (params: S3.GetObjectRequest) => {
	console.log(`Fetching mail content from ${buildS3Url(params)}`);
	try {
		const { Body: body } = await s3Client.getObject(params).promise();
		if (!body) {
			throw new Error('Received empty Body');
		}
		return body.toString();
	} catch (error) {
		console.error(error);
		throw new Error(`Failed to get mail content from S3 <${buildS3Url(params)}>: ${error.message}`);
	}
};

/** Return processed message for forwarding, de-duping headers */
const processMessage = (origMessage: string, firstOrigRecipient: string) => {
	console.log(`Original message:\n\n${origMessage}`);
	const lines = origMessage.split('\r\n');
	const headers: { [key: string]: string } = {};
	const newMessageLines: string[] = [];
	let currentHeader: string[] = [];
	let inHeaders = true;
	let origFrom = '';
	lines.forEach((line) => {
		if (inHeaders) {
			if (line.match(/^\s/)) {
				// continuation of multi-line header
				if (!currentHeader) {
					throw new Error('Message started with space');
				}
				currentHeader.push(line);
			} else {
				// new header line
				if (currentHeader.length > 0) {
					// process the buffered header
					const headerLine = currentHeader.join(' ');
					const match = headerLine.match(/^([A-Za-z0-9-]+): (.*)$/);
					if (!match) {
						console.error(`Failed to parse header:\n${headerLine}`);
						throw new Error('Failed to parse message headers');
					}
					const headerKey = match[1];
					let headerValue = match[2];
					const lowerHeaderKey = headerKey.toLowerCase();
					if (headerKey.match(excludeHeaderPattern)) {
						console.log(`Omitting excluded header: ${headerKey}`);
					} else if (Object.prototype.hasOwnProperty.call(headers, lowerHeaderKey)
						&& !headerKey.match(allowDuplicateHeaderPatten)) {
						console.log(`Omitting duplicate header: ${headerKey}`);
					} else {
						// handle special header rules
						if (lowerHeaderKey === 'from') {
							// SES does not allow sending messages from an unverified address,
							// so replace the message's "From:" header with the first original
							// recipient (which should be a verified domain)
							origFrom = headerValue;
							const from = origFrom.replace(/"/g, '')
								.replace(/</g, '(')
								.replace(/>/g, ')');
							headerValue = `"${from}" <${firstOrigRecipient}>`;
							currentHeader = [`${headerKey}: ${headerValue}`];
						}
						// store condensed header value for reference
						headers[lowerHeaderKey] = headerValue;
						// add the buffered header lines to the new message
						newMessageLines.push(...currentHeader);
					}
					currentHeader = [];
				}

				if (line === '') {
					// end of headers
					inHeaders = false;

					if (Object.keys(headers).length === 0) {
						throw new Error('Message had no headers (started with blank line)');
					}

					// add reply-to header if none included
					if (headers['reply-to']) {
						console.log(`Message already has Reply-To value: ${headers['reply-to']}`);
					} else if (origFrom) {
						console.log(`Adding Reply-To address: ${origFrom}`);
						newMessageLines.push(`Reply-To: ${origFrom}`);
					} else {
						console.error('Reply-To address not added because From address was not found');
					}

					// add the blank line to the new message
					newMessageLines.push(line);
				} else {
					// start a new header buffer
					currentHeader = [line];
				}
			}
		} else {
			// add body line to message
			newMessageLines.push(line);
		}
	});

	const newMessage = newMessageLines.join('\r\n');
	return newMessage;
};

const forwardMessage = async (
	newRecipients: string[],
	firstOrigRecipient: string,
	message: string,
) => {
	const params = {
		Destinations: newRecipients,
		Source: firstOrigRecipient,
		RawMessage: {
			Data: message,
		},
	};

	console.log(`Sending email via SES ${firstOrigRecipient} -> [${newRecipients.join(', ')}]`);
	console.log(JSON.stringify(params, null, 2));

	try {
		await sesClient.sendRawEmail(params).promise();
	} catch (error) {
		console.error(error);
		throw new Error(`Failed to forward email: ${error.message}`);
	}
};

const reportError = async (
	mailError: any,
	s3Url: string,
	origMessage: string,
) => {
	const errorMessage = mailError?.message;
	let message = `Reba failed to process a message with ${errorMessage ? 'the following error:' : 'an unknown error.'}\n\n`;
	if (errorMessage) {
		message += `  ${errorMessage}\n\n`;
	}
	if (s3Url) {
		message += `Message S3 object: ${s3Url}\n\n`;
	}
	if (origMessage) {
		message += `Original message follows:\n\n${origMessage}\n`;
	}
	const params = {
		Destination: {
			ToAddresses: [
				config.postmaster,
			],
		},
		Source: config.postmaster,
		Message: {
			Body: {
				Text: {
					Charset: 'UTF-8',
					Data: message,
				},
			},
			Subject: {
				Charset: 'UTF-8',
				Data: '[Reba] Mail processing failure',
			},
		},
	};
	try {
		await sesClient.sendEmail(params).promise();
	} catch (error) {
		console.error(error);
		console.error('Additionally, failed to send error message to postmaster');
	}
};

exports.handler = lambda(async ({ event }) => {
	console.log('Event:', JSON.stringify(event, null, 2));
	const record = validateSesEvent(event);
	let s3Url = '';
	let origMessage = '';

	try {
		const [mail, origRecipients] = parseRecord(record);
		const [newRecipients, firstOrigRecipient] = processAliases(origRecipients);

		if (newRecipients.length === 0) {
			console.log('No recipients after alias processing, let it bounce');
			return { disposition: 'CONTINUE' };
		}

		const s3Params = buildS3Params(mail);
		s3Url = buildS3Url(s3Params);

		origMessage = await fetchMessage(s3Params);
		const message = processMessage(origMessage, firstOrigRecipient);

		await forwardMessage(newRecipients, firstOrigRecipient, message);
	} catch (error) {
		console.error(error);
		console.error('Failed to process message, notifying postmaster');
		await reportError(error, s3Url, origMessage);
	}
	return { disposition: 'STOP_RULE' };
});
