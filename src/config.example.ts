const config = {
	postmaster: 'you@yourteam.awsapps.com',
	aliases: [
		{
			pattern: /@yourdomain\.com$/i,
			rejectPattern: /^(spamaddress|otherspam)@/i,
			recipients: ['you@yourteam.awsapps.com'],
		},
		{
			pattern: /^buddy@yourotherdomain\.org$/i,
			recipients: ['buddy@yourteam.awsapps.com'],
		},
		{
			pattern: /^wholeteam@yourotherdomain\.org$/i,
			recipients: [
				'you@yourteam.awsapps.com',
				'buddy@yourteam.awsapps.com',
			],
		},
	],
};

export default config;
