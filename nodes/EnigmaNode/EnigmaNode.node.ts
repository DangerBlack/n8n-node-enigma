import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
} from 'n8n-workflow';
import Enigma from '@cubbit/enigma';

//icon: 'file:sqlite-icon.svg',
export class EnigmaNode implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Enigma Node',
		name: 'enigmaNode',
		
		group: ['transform'],
		version: 1,
		description: 'Cryptographic functions for encrypting and decrypting data',
		defaults: {
			name: 'Enigma',
		},
		inputs: ['main'],
		outputs: ['main'],
		properties: [
			// Node properties which the user gets displayed and
			// can change on the node.
			{
				displayName: 'Cryptographic Utilities',
				name: 'cryptographic_utilities',
				type: 'options',
				default: 'AES_256',
				noDataExpression: true,
				required: true,
				options: [
					{
						name: 'AES_256',
						value: 'AES_256',
						description: 'Encrypt and decrypt data using AES 256',
					},
					{
						name: 'ECC',
						value: 'ECC',
						description: 'Encrypt and decrypt data using ECC',
					},
					{
						name: 'HASH',
						value: 'HASH',
						description: 'Generate a HASH SHA 256/SHA 1 hash of the input',
					},
					{
						name: 'RANDOM',
						value: 'RANDOM',
						description: 'Generate a random string',
					},
					{
						name: 'RSA',
						value: 'RSA',
						description: 'Encrypt and decrypt data using RSA',
					},
				],
			},
			{
				displayName: 'Message',
				name: 'message',
				type: 'string',
				default: '',
				placeholder: 'text to encrypt/decrypt',
				description: 'The message to encrypt or decrypt',
				required: true,
				typeOptions: {
					rows: 8,
				},
			},
			{
				displayName: 'Algorithm',
				name: 'hash_algorithm',
				type: 'options',
				default: 'SHA256',
				description: 'The algorithm to use for the hash',
				options: [
					{
						name: 'SHA 256',
						value: 'SHA256',
						description: 'Generate a SHA 256 hash of the input',
					},
					{
						name: 'SHA 1',
						value: 'SHA1',
						description: 'Generate a SHA 1 hash of the input',
					},
				],
				displayOptions: {
					show: {
						cryptographic_utilities: [
							'HASH',
						],
					},
				},				
			},
			{
				displayName: 'Encoding',
				name: 'hash_encoding',
				type: 'options',
				default: 'BASE64',
				description: 'The encoding to use for the hash',
				options: [
					{
						name: 'BASE 64',
						value: 'BASE64',
						description: 'Use base 64 encoding',
					},
					{
						name: 'BASE 58',
						value: 'BASE58',
						description: 'Use base 58 encoding',
					},
					{
						name: 'HEX',
						value: 'HEX',
						description: 'Use hex encoding',
					},
				],
				displayOptions: {
					show: {
						cryptographic_utilities: [
							'HASH',
						],
					},
				},				
			},
			{
				displayName: 'Encrypt/Decrypt',
				name: 'operation',
				type: 'options',
				noDataExpression: true,
				default: 'encrypt',
				description: 'Encrypt or decrypt the input',
				options: [
					{
						name: 'Encrypt',
						value: 'encrypt',
						description: 'Encrypt the input',
						action: 'Encrypt the input',
					},
					{
						name: 'Decrypt',
						value: 'decrypt',
						description: 'Decrypt the input',
						action: 'Decrypt the input',
					},
				],
				displayOptions: {
					show: {
						cryptographic_utilities: [
							'AES_256',
						],
					},
				},				
			},
			{
				displayName: 'Encryption/Decryption Key',
				name: 'aes_key',
				type: 'string',
				default: '',
				description: 'An encryption key for the AES 256 encryption in base64 format',
				displayOptions: {
					show: {
						cryptographic_utilities: [
							'AES_256',
						],
					},
				},				
			},
			{
				displayName: 'IV',
				name: 'aes_256_iv',
				type: 'string',
				default: '',
				description: 'An initialization vector for the AES 256 encryption in base64 format',
				displayOptions: {
					show: {
						operation: [
							'encrypt',
						],
						cryptographic_utilities: [
							'AES_256',
						],
					},
				},				
			}
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> 
	{
		const items = this.getInputData();
		let item: INodeExecutionData;

		for(let itemIndex = 0; itemIndex < items.length; itemIndex++) 
		{
			try 
			{
				item = items[itemIndex];
				let cryptographic_utilities = this.getNodeParameter('cryptographic_utilities', itemIndex, '') as string;
				let message = this.getNodeParameter('message', itemIndex, '') as string;
				
				switch(cryptographic_utilities)
				{
					case 'AES_256':
						const ivSize = 16;  // For AES-GCM (128 bits)
						const tagSize = 16; // For AES-GCM (128 bits)
						let operation = this.getNodeParameter('operation', itemIndex, '') as string;
						let aes_key = this.getNodeParameter('aes_key', itemIndex, '') as string;
						
						if(operation == 'encrypt')
						{
							const enigma = new Enigma.AES();
							const options: Enigma.AES.Options = {};

							if(aes_key.length > 0)
								options.key = Buffer.from(aes_key, 'base64');

							const aes = await enigma.init(options);
							const result = await aes.encrypt(message);
							item.json.key = aes.key.toString('base64');
							item.json.encrypted = Buffer.concat([result.content, result.iv, result.tag || Buffer.alloc(0)]).toString('base64');
							
							break;
						}
						else
						{
							const encrypted_buffer = Buffer.from(message, 'base64');
							const contentSize = encrypted_buffer.length - (ivSize + tagSize);
							const content = encrypted_buffer.subarray(0, contentSize);
							const iv = encrypted_buffer.subarray(contentSize, contentSize + ivSize);
							const tag = encrypted_buffer.subarray(contentSize + ivSize, contentSize + ivSize + tagSize);

							const enigma = new Enigma.AES();
							const options: Enigma.AES.Options = {};

							if(aes_key.length > 0)
								options.key = Buffer.from(aes_key, 'base64');

							const aes = await enigma.init(options);
							const result = await aes.decrypt({ content, iv, tag });
							item.json.decrypted = result.toString();
							break;
						}
					case 'ECC':
						// const enigma = new Enigma();
						// item.json.result = enigma.encrypt(this.getNodeParameter('query', itemIndex, '') as string);
						break;
					case 'RANDOM':
						// const enigma = new Enigma();
						// item.json.result = enigma.encrypt(this.getNodeParameter('query', itemIndex, '') as string);
						break;
					case 'RSA':
						// const enigma = new Enigma();
						// item.json.result = enigma.encrypt(this.getNodeParameter('query', itemIndex, '') as string);
						break;
					case 'HASH':
						let algorithm = this.getNodeParameter('hash_algorithm', itemIndex, '') as Enigma.Hash.Algorithm;
						let encoding = this.getNodeParameter('hash_encoding', itemIndex, '') as Enigma.Hash.Encoding;
						
						item.json.hash = await Enigma.Hash.digest(message, { algorithm, encoding })
						break;
				}
			} 
			catch(error) 
			{
				// This node should never fail but we want to showcase how
				// to handle errors.
				if(this.continueOnFail()) 
				{
					items.push({ json: this.getInputData(itemIndex)[0].json, error, pairedItem: itemIndex });
				} 
				else 
				{
					// Adding `itemIndex` allows other workflows to handle this error
					if(error.context) 
					{
						// If the error thrown already contains the context property,
						// only append the itemIndex
						error.context.itemIndex = itemIndex;
						throw error;
					}

					throw new NodeOperationError(this.getNode(), error, {
						itemIndex,
					});
				}
			}
		}

		return this.prepareOutputData(items);
	}
}