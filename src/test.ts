import { Context, SESEvent } from 'aws-lambda';

import { handler } from './index';
import event from './event.json';

handler(event as SESEvent, {} as Context, () => {})
	?.then((data) => {
		console.log('Success:', data);
	})
	.catch((error) => {
		console.log('Failure:', error);
	});
