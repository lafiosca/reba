import { lambda, LambdaEvent } from 'nice-lambda';
import AWS from 'aws-sdk';

import config from './config';
import { readFileSync } from 'fs';
import { resolve } from 'path';

const emailBucket = process.env.S3BucketEmail ?? '';
const emailPrefix = process.env.S3PrefixEmail ?? '';

const s3Client = new AWS.S3();
const sesClient = new AWS.SES();

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
					firstOrigRecipient = firstOrigRecipient ?? origRecipient;
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

/** Fetch mail message body from S3, or undefined if error */
const fetchMessage = async (mail: SESRecordMail) => {
	const params = {
		Bucket: emailBucket,
		Key: `${emailPrefix}${mail.messageId}`,
	};
	const s3Url = `s3://${params.Bucket}/${params.Key}`;
	console.log(`Fetching mail content from ${s3Url}`);
	try {
		const { Body: body } = await s3Client.getObject(params).promise();
		if (!body) {
			throw new Error('Received empty Body');
		}
		return body.toString();
	} catch (error) {
		console.error(error);
		throw new Error(`Failed to get mail content from S3 <${s3Url}>: ${error.message}`);
	}
};

/** Return processed message for forwarding */
const processMessage = (message: string, firstOrigRecipient: string) => {
	console.log(`Original message:\n${message}`);

	let match = message.match(/^((?:.+\r?\n)*)(\r?\n(?:.*\s+)*)/m);

	let header = match ? match[1] : message;
	const body = match ? match[2] : '';

	// Add "Reply-To:" with the "From" address if it doesn't already exist
	match = header.match(/^Reply-To: (.*\r?\n)/im);

	if (match) {
		console.log(`Reply-To address already exists: ${match[1]}`);
	} else {
		console.log('No Reply-To address found');
		match = header.match(/^From: (.*\r?\n)/m);
		if (match) {
			console.log(`Adding Reply-To address: ${match[1]}`);
			header = `${header}Reply-To: ${match[1]}`;
		} else {
			console.error('Reply-To address not added because From address was not found');
		}
	}

	// SES does not allow sending messages from an unverified address,
	// so replace the message's "From:" header with the original
	// recipient (which is a verified domain)
	header = header.replace(
		/^From: (.*)/mg,
		(fromLine, from) => {
			const fromName = from.replace(/"/g, '')
				.replace(/</g, '(')
				.replace(/>/g, ')');
			return `From: "${fromName}" <${firstOrigRecipient}>`;
		},
	);

	// Remove the Return-Path header
	header = header.replace(/^Return-Path: (.*)\r?\n/mg, '');

	// Remove Sender header
	header = header.replace(/^Sender: (.*)\r?\n/mg, '');

	// Remove all DKIM-Signature headers to prevent triggering an
	// "InvalidParameterValue: Duplicate header 'DKIM-Signature'" error.
	// These signatures will likely be invalid anyways, since the From
	// header was modified.
	header = header.replace(/^DKIM-Signature: .*\r?\n(\s+.*\r?\n)*/mg, '');

	return `${header}${body}`;
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

exports.handler = lambda(async ({ event }) => {
	console.log('Event:', JSON.stringify(event, null, 2));
	const record = validateSesEvent(event);

	try {
		const [mail, origRecipients] = parseRecord(record);
		const [newRecipients, firstOrigRecipient] = processAliases(origRecipients);

		if (newRecipients.length === 0) {
			console.log('No recipients after alias processing, let it bounce');
			return { disposition: 'CONTINUE' };
		}

		const origMessage = await fetchMessage(mail);
		const message = processMessage(origMessage, firstOrigRecipient);

		await forwardMessage(newRecipients, firstOrigRecipient, message);
	} catch (error) {
		console.error(error);
		console.error('Failed to process message, notifying postmaster');
		// TODO: notify postmaster
	}
	return { disposition: 'STOP_RULE' };
});

// DEBUGGING:
(async () => {
	const data = readFileSync(resolve('./message.txt')).toString();
	processMessage(data, '');
})();
