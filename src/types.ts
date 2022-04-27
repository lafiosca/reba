type RequireKeys<T, K extends keyof T> = Pick<Required<T>, K> & Omit<T, K>;

interface ConfigRuleMatchOptions {
	matchExact?: string;
	matchHost?: string;
	matchPattern?: RegExp;
}

type ConfigRuleMatch = (
	| RequireKeys<ConfigRuleMatchOptions, 'matchExact'>
	| RequireKeys<ConfigRuleMatchOptions, 'matchHost'>
	| RequireKeys<ConfigRuleMatchOptions, 'matchPattern'>
);

type ConfigRule = ConfigRuleMatch & {
	/** Reject senders matching pattern */
	rejectPattern?: RegExp;
	/** Reject user parts in this list */
	rejectUsers?: string[];
	/** Bypass all reject conditions for this rule, including globals */
	allowAll?: true;
	/** List of alias recipients to forward message to */
	recipients: string[];
};

export interface Config {
	postmaster: string;
	rules: ConfigRule[];
	globalRules?: {
		rejectIfSubjectContains?: string[],
	},
}

export interface SESRecordMail {
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
export interface SESRecordReceipt {
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

export interface SESRecord {
	eventSource: 'aws:ses';
	eventVersion: '1.0';
	ses: {
		mail: SESRecordMail;
		receipt: SESRecordReceipt;
	};
}
