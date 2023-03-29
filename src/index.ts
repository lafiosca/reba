/* eslint-disable import/prefer-default-export */
import { S3, SES } from 'aws-sdk';
import {
	SESEvent,
	Handler,
	SESEventRecord,
	SESMail,
} from 'aws-lambda';

import config from './config';

type SESHandler = Handler<SESEvent, { disposition: 'CONTINUE' | 'STOP_RULE' }>;

const emailBucket = process.env.S3BucketEmail ?? '';
const emailPrefix = process.env.S3PrefixEmail ?? '';
const suppressSend = process.env.SuppressSend === 'yes';

const excludeHeaderPattern = /^(?:Return-Path|Sender|DKIM-Signature)$/i;
const excludeIfEmptyHeaderPattern = /^(?:Reply-To)$/i;
const allowDuplicateHeaderPatten = /^(?:Received)$/i;

const s3Client = new S3();
const sesClient = new SES();

/** Does a semi-thorough validation of Lambda event to ensure it looks like what we expect from SES */
const validateSesEvent = (event: SESEvent): SESEventRecord => {
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
const parseRecord = (record: SESEventRecord): [SESMail, string[]] => {
	console.log('Parsing SES record');

	const { mail, receipt: { recipients } } = record.ses;

	if (!recipients || !Array.isArray(recipients) || recipients.length === 0) {
		throw new Error('Record did not contain recipients');
	}

	return [mail, recipients.map((recipient) => recipient.toLowerCase())];
};

/** Process alias forwarding rules for original recipients */
const processRules = (origRecipients: string[], subject: string): [string[], string] => {
	console.log(`Processing rules for original recipients: ${JSON.stringify(origRecipients, null, 2)}`);
	const {
		rules,
		globalRules: {
			rejectIfSubjectContains: rejectIfSubjectContainsGlobal,
		} = {},
	} = config;
	let firstOrigRecipient = '';
	const newRecipients: string[] = [];
	origRecipients.forEach((origRecipient) => {
		let matched = false;
		for (let i = 0; !matched && i < rules.length; i += 1) {
			const {
				matchExact,
				matchHost,
				matchPattern,
				rejectUsers,
				rejectPattern,
				rejectIfSubjectContains,
				allowAll,
				recipients: aliasRecipients,
			} = rules[i];
			// Check if the rule is valid, just in case
			if (matchExact || matchHost || matchPattern) {
				const [origUser, origHost] = origRecipient.split('@');
				// First, see if the recipient matches this rule
				matched = true;
				if (matchExact && origRecipient !== matchExact) {
					matched = false;
				}
				if (matched && matchHost && origHost !== matchHost) {
					matched = false;
				}
				if (matched && matchPattern && !origRecipient.match(matchPattern)) {
					matched = false;
				}
				// If the recipient matches, process rule
				if (matched) {
					let rejected = false;
					if (!allowAll) {
						// Check rule's reject conditions
						if (rejectUsers?.includes(origUser)) {
							rejected = true;
							console.log(`Recipient '${origRecipient}' was in rejectUsers list for rule #${i}`);
						}
						if (!rejected && rejectPattern && origRecipient.match(rejectPattern)) {
							rejected = true;
							console.log(`Recipient '${origRecipient}' matched rejectPattern for rule #${i}`);
						}
						if (!rejected && rejectIfSubjectContains) {
							for (let ri = 0; !rejected && ri < rejectIfSubjectContains.length; ri += 1) {
								const rejectItem = rejectIfSubjectContains[ri];
								if (typeof rejectItem === 'string') {
									if (subject.includes(rejectItem)) {
										rejected = true;
										console.log(`Subject header '${subject}' contained rejected string '${rejectItem}'`);
									}
								} else if (subject.match(rejectItem)) {
									rejected = true;
									console.log(`Subject header '${subject}' matched rejected pattern '${rejectItem}'`);
								}
							}
						}
						if (!rejected && rejectIfSubjectContainsGlobal) {
							for (let ri = 0; !rejected && ri < rejectIfSubjectContainsGlobal.length; ri += 1) {
								const rejectItem = rejectIfSubjectContainsGlobal[ri];
								if (typeof rejectItem === 'string') {
									if (subject.includes(rejectItem)) {
										rejected = true;
										console.log(`Subject header '${subject}' contained globally rejected string '${rejectItem}'`);
									}
								} else if (subject.match(rejectItem)) {
									rejected = true;
									console.log(`Subject header '${subject}' matched globally rejected pattern '${rejectItem}'`);
								}
							}
						}
					}
					if (rejected) {
						// Do nothing; because we matched, no further rules will be processed
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
		}
	});
	return [newRecipients, firstOrigRecipient];
};

const buildS3Params = (mail: SESMail): S3.GetObjectRequest => ({
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
	} catch (error: any) {
		console.error(error);
		throw new Error(`Failed to get mail content from S3 <${buildS3Url(params)}>: ${error?.message ?? error}`);
	}
};

/** Return processed message for forwarding, de-duping headers */
const processMessage = (origMessage: string, firstOrigRecipient: string): string | undefined => {
	const rejectIfBodyLineContains = config.globalRules?.rejectIfBodyLineContains ?? [];
	console.log(`Original message:\n\n${origMessage}`);
	const lines = origMessage.split('\r\n');
	const headers: { [key: string]: string } = {};
	const newMessageLines: string[] = [];
	let currentHeader: string[] = [];
	let inHeaders = true;
	let origFrom = '';
	for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
		const line = lines[lineIndex];
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
					const match = headerLine.match(/^([^\s:]+):\s?(.*)$/);
					if (!match) {
						throw new Error(`Failed to parse message header:\n${headerLine}`);
					}
					const headerKey = match[1];
					let headerValue = match[2];
					const lowerHeaderKey = headerKey.toLowerCase();
					if (headerKey.match(excludeHeaderPattern)) {
						console.log(`Omitting excluded header: ${headerKey}`);
					} else if (headerKey.match(excludeIfEmptyHeaderPattern) && !headerValue.trim()) {
						console.log(`Omitting excluded empty header: ${headerKey}`);
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
			// eslint-disable-next-line no-restricted-syntax
			for (const rejectPattern of rejectIfBodyLineContains) {
				if (typeof rejectPattern === 'string') {
					if (line.includes(rejectPattern)) {
						console.log(`Body line (index ${lineIndex}) contained globally rejected string '${rejectPattern}'`);
						return undefined;
					}
				} else if (line.match(rejectPattern)) {
					console.log(`Body line (index ${lineIndex}) contained globally rejected pattern '${rejectPattern}'`);
					return undefined;
				}
			}
			// add body line to message
			newMessageLines.push(line);
		}
	}

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

	if (suppressSend) {
		console.log('Would send raw email here:', params);
	} else {
		try {
			await sesClient.sendRawEmail(params).promise();
		} catch (error: any) {
			console.error(error);
			throw new Error(`Failed to forward email: ${error?.message ?? error}`);
		}
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
	if (suppressSend) {
		console.log('Would send email here:', params);
	} else {
		try {
			await sesClient.sendEmail(params).promise();
		} catch (error) {
			console.error(error);
			console.error('Additionally, failed to send error message to postmaster');
		}
	}
};

export const handler: SESHandler = async (event: SESEvent) => {
	console.log('Event:', JSON.stringify(event, null, 2));
	const record = validateSesEvent(event);
	let s3Url = '';
	let origMessage = '';

	try {
		const [mail, origRecipients] = parseRecord(record);
		const [newRecipients, firstOrigRecipient] = processRules(origRecipients, mail.commonHeaders.subject ?? '');

		if (newRecipients.length === 0) {
			console.log('No recipients after alias processing, let it bounce');
			return { disposition: 'CONTINUE' };
		}

		const s3Params = buildS3Params(mail);
		s3Url = buildS3Url(s3Params);

		origMessage = await fetchMessage(s3Params);
		const message = processMessage(origMessage, firstOrigRecipient);

		if (message === undefined) {
			console.log('Message was rejected during body processing');
			return { disposition: 'CONTINUE' };
		}

		await forwardMessage(newRecipients, firstOrigRecipient, message);
	} catch (error) {
		console.error(error);
		console.error('Failed to process message, notifying postmaster');
		await reportError(error, s3Url, origMessage);
	}
	return { disposition: 'STOP_RULE' };
};
