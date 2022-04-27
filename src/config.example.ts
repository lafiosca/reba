import { Config } from './types';

const config: Config = {
	postmaster: 'you@yourteam.awsapps.com',
	globalRules: {
		rejectIfSubjectContains: ['MAKE.MONEY.FAST'],
	},
	rules: [
		{
			matchHost: 'yourdomain.com',
			rejectUsers: [
				'bad',
				'null',
			],
			recipients: ['you@yourteam.awsapps.com'],
		},
		{
			matchExact: 'buddy@yourotherdomain.org',
			recipients: ['buddy@yourteam.awsapps.com'],
		},
		{
			matchPattern: /^(biz|legal)@yourotherdomain\.org$/i,
			recipients: [
				'you@yourteam.awsapps.com',
				'buddy@yourteam.awsapps.com',
			],
		},
		{
			matchPattern: /^(abuse|admin|(web|post|host)master)@/i,
			allowAll: true,
			recipients: ['you@yourteam.awsapps.com'],
		},
	],
};

export default config;
