import {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
} from 'n8n-workflow';
import Enigma from '@cubbit/enigma';

//
export class EnigmaNode implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Enigma Node',
		name: 'enigmaNode',
		icon: 'file:enigma-icon.svg',
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
				displayName: 'Message',
				name: 'hash_message',
				type: 'string',
				default: '',
				placeholder: 'text to encrypt/decrypt',
				description: 'The message to encrypt or decrypt',
				typeOptions: {
					rows: 8,
				},
				displayOptions: {
					show: {
						cryptographic_utilities: [
							'HASH',
						],
					},
				},	
			},
			{
				displayName: 'Encrypt/Decrypt/Key Generation',
				name: 'aes_operation',
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
					{
						name: 'Key Generation',
						value: 'key_generation',
						description: 'Generate a new AES 256 key',
						action: 'Generate a new AES 256 key',
					}
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
						aes_operation: [
							'encrypt',
							'decrypt',
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
						aes_operation: [
							'encrypt',
						],
						cryptographic_utilities: [
							'AES_256',
						],
					},
				},				
			},
			{
				displayName: 'Message',
				name: 'aes_message',
				type: 'string',
				default: '',
				placeholder: 'text to encrypt/decrypt',
				description: 'The message to encrypt or decrypt',
				typeOptions: {
					rows: 8,
				},
				displayOptions: {
					show: {
						cryptographic_utilities: [
							'AES_256',
						],
						aes_operation: [
							'encrypt',
							'decrypt',
						],
						use_binary:	[false]
					},
				},	
			},
			{
				displayName: 'Encrypt/Decrypt/Key Generation',
				name: 'rsa_operation',
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
					{
						name: 'Key Generation',
						value: 'key_generation',
						description: 'Generate a new RSA key pair',
						action: 'Generate a new RSA key pair',
					},
				],
				displayOptions: {
					show: {
						cryptographic_utilities: [
							'RSA',
						],
					},
				},				
			},
			{
				displayName: 'Public Key',
				name: 'rsa_public_key',
				type: 'string',
				default: '',
				description: 'A public key for the RSA encryption in base64 format',
				displayOptions: {
					show: {
						rsa_operation: [
							'encrypt',
							'decrypt',
						],
						cryptographic_utilities: [
							'RSA',
						],
					},
				},				
			},
			{
				displayName: 'Private Key',
				name: 'rsa_private_key',
				type: 'string',
				default: '',
				description: 'A private key for the RSA encryption in base64 format',
				displayOptions: {
					show: {
						rsa_operation: [
							'encrypt',
							'decrypt',
						],
						cryptographic_utilities: [
							'RSA',
						],
					},
				},				
			},
			{
				displayName: 'Message',
				name: 'rsa_message',
				type: 'string',
				default: '',
				placeholder: 'text to encrypt/decrypt',
				description: 'The message to encrypt or decrypt',
				typeOptions: {
					rows: 8,
				},
				displayOptions: {
					show: {
						cryptographic_utilities: [
							'RSA',
						],
						rsa_operation: [
							'encrypt',
							'decrypt',
						],
					},
				},	
			},
			{
				displayName: 'Sign/Verify/Key Generation',
				name: 'ecc_operation',
				type: 'options',
				noDataExpression: true,
				default: 'sign',
				description: 'Sign or verify the input',
				options: [
					{
						name: 'Sign',
						value: 'sign',
						description: 'Sign the input with ED25519',
						action: 'Sign the input with ED25519',
					},
					{
						name: 'Verify',
						value: 'verify',
						description: 'Verify the input with ED25519',
						action: 'Verify the input with ED25519',
					},
					{
						name: 'Key Generation',
						value: 'key_generation',
						description: 'Generate a new ED25519 key pair',
						action: 'Generate a new ED25519 key pair',
					},
				],
				displayOptions: {
					show: {
						cryptographic_utilities: [
							'ECC',
						],
					},
				},				
			},
			{
				displayName: 'Public Key',
				name: 'ecc_public_key',
				type: 'string',
				default: '',
				description: 'A public key for the ECC encryption in base64 format',
				displayOptions: {
					show: {
						ecc_operation: [
							'sign',
							'verify',
						],
						cryptographic_utilities: [
							'ECC',
						],
					},
				},				
			},
			{
				displayName: 'Private Key',
				name: 'ecc_private_key',
				type: 'string',
				default: '',
				description: 'A private key for the ECC encryption in base64 format',
				displayOptions: {
					show: {
						ecc_operation: [
							'sign',
						],
						cryptographic_utilities: [
							'ECC',
						],
					},
				},				
			},
			{
				displayName: 'Signature',
				name: 'ecc_signature',
				type: 'string',
				default: '',
				description: 'A signature for the ECC encryption in base64 format',
				displayOptions: {
					show: {
						ecc_operation: [
							'verify',
						],
						cryptographic_utilities: [
							'ECC',
						],
					},
				},				
			},
			{
				displayName: 'Message',
				name: 'ecc_message',
				type: 'string',
				default: '',
				placeholder: 'text to encrypt/decrypt',
				description: 'The message to encrypt or decrypt',
				typeOptions: {
					rows: 8,
				},
				displayOptions: {
					show: {
						cryptographic_utilities: [
							'ECC',
						],
						ecc_operation: [
							'sign',
							'verify',
						],
					},
				},	
			},
			{
				displayName: 'Size',
				name: 'string_size',
				type: 'number',
				default: 32,
				placeholder: '32',
				description: 'The byte size of the random string',
				typeOptions: {
					minValue: 1,
					maxValue: 4096,
				},
				displayOptions: {
					show: {
						cryptographic_utilities: [
							'RANDOM',
						],
					},
				},	
			},
			{
				displayName: 'Use Binary File',
				name: 'use_binary',
				type: 'boolean',
				default: false,
				description: 'Whether process a binary file instead of text',
				displayOptions: {
					show: {
						cryptographic_utilities: ['AES_256'], // adjust based on your context
					},
				},
			},
			{
				displayName: 'Binary Property Name',
				name: 'binary_property_name',
				type: 'string',
				default: 'data',
				description: 'Name of the binary property to use (usually "data")',
				displayOptions: {
					show: {
						cryptographic_utilities: ['AES_256'],
						aes_operation: [
							'encrypt',
							'decrypt',
						],
						use_binary: [true],
					},
				},
			},
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
				
				switch(cryptographic_utilities)
				{
					case 'AES_256':
						const ivSize = 16;  // For AES-GCM (128 bits)
						const tagSize = 16; // For AES-GCM (128 bits)
						let aes_operation = this.getNodeParameter('aes_operation', itemIndex, '') as string;
						let aes_key = this.getNodeParameter('aes_key', itemIndex, '') as string;
						let aes_256_iv = this.getNodeParameter('aes_256_iv', itemIndex, '') as string;

						const use_binary = this.getNodeParameter('use_binary', itemIndex) as boolean;
						let binaryData: Buffer | undefined;
						let aes_message: string | Buffer = '';
						if(use_binary)
						{
							const binaryPropertyName = this.getNodeParameter('binary_property_name', itemIndex) as string;
							binaryData = await this.helpers.getBinaryDataBuffer(itemIndex, binaryPropertyName);
						}
						else
							aes_message = this.getNodeParameter('aes_message', itemIndex, '') as string;

						if(use_binary && binaryData)
							aes_message = binaryData;

						switch(aes_operation)
						{
							case 'key_generation':
								await aes_keygen(item)
								break;
							case 'encrypt':
								await aes_encrypt(this, item, aes_key, aes_256_iv, aes_message, use_binary)
								break;
							case 'decrypt':
								await aes_decrypt(this, item, aes_key, aes_message, ivSize, tagSize, use_binary)
								break;
						}
						break;
					case 'ECC':
						let ecc_operation = this.getNodeParameter('ecc_operation', itemIndex, '') as string;
						let ecc_public_key = this.getNodeParameter('ecc_public_key', itemIndex, '') as string;
						let ecc_private_key = this.getNodeParameter('ecc_private_key', itemIndex, '') as string;
						let ecc_signature = this.getNodeParameter('ecc_signature', itemIndex, '') as string;
						let ecc_message = this.getNodeParameter('ecc_message', itemIndex, '') as string;

						switch(ecc_operation)
						{
							case 'key_generation':
								await ecc_keygen(item)
								break;
							case 'sign':
								await ecc_sign(item, ecc_public_key, ecc_private_key, ecc_message)
								break;
							case 'verify':
								await ecc_verify(item, ecc_public_key, ecc_message, ecc_signature)
								break;
						}
						break;
					case 'RANDOM':
						const size = this.getNodeParameter('string_size', itemIndex, 32) as number;
						const random = Enigma.Random.bytes(size);
						item.json.random = random.toString('base64');
    					break;
					case 'RSA':
						let rsa_operation = this.getNodeParameter('rsa_operation', itemIndex, '') as string;
						let rsa_public_key = this.getNodeParameter('rsa_public_key', itemIndex, '') as string;
						let rsa_private_key = this.getNodeParameter('rsa_private_key', itemIndex, '') as string;
						let rsa_message = this.getNodeParameter('rsa_message', itemIndex, '') as string;

						switch(rsa_operation)
						{
							case 'key_generation':
								await rsa_keygen(item)
								break;
							case 'encrypt':
								await ras_encrypt(item, rsa_public_key, rsa_private_key, rsa_message)
								break;
							case 'decrypt':
								await ras_decrypt(item, rsa_public_key, rsa_private_key, rsa_message)
								break;
						}
						break;
					case 'HASH':
						let algorithm = this.getNodeParameter('hash_algorithm', itemIndex, '') as Enigma.Hash.Algorithm;
						let encoding = this.getNodeParameter('hash_encoding', itemIndex, '') as Enigma.Hash.Encoding;
						let message = this.getNodeParameter('hash_message', itemIndex, '') as string;

						
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
					items.push({
						json: {
							error: (error as Error).message || 'Unknown error',
						},
						pairedItem: {
							item: itemIndex,
						},
					});
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
						message: error.message,
					});
				}
			}
		}

		return this.prepareOutputData(items);
	}
}

async function aes_keygen(item: INodeExecutionData)
{
	const enigma = new Enigma.AES();
	const aes = await enigma.init();
	item.json.key = aes.key.toString('base64');
}

async function aes_encrypt(self: IExecuteFunctions, item: INodeExecutionData, aes_key: string, aes_256_iv: string, message: string | Buffer, isBinary: boolean = false)
{
	const enigma = new Enigma.AES();
	const options: Enigma.AES.Options = {};

	if(aes_key.length > 0)
		options.key = Buffer.from(aes_key, 'base64');
	else
	{
		// eslint-disable-next-line n8n-nodes-base/node-execute-block-wrong-error-thrown
		throw new Error('AES key is required for encryption');
	} 

	const aes = await enigma.init(options);
	let result: {
		content: Buffer;
		iv: Buffer;
		tag?: Buffer;
	};
	
	if(aes_256_iv == '')
		result = await aes.encrypt(message);
	else 
		result = await aes.encrypt(message, Buffer.from(aes_256_iv, 'base64'));

	item.json.key = aes.key.toString('base64');
	const encrypted = Buffer.concat([result.content, result.iv, result.tag || Buffer.alloc(0)]);
	if(!isBinary)
		item.json.encrypted = encrypted.toString('base64');
	else
	item.binary = {
		data: await self.helpers.prepareBinaryData(
			encrypted,
			'decrypted_file.dat',
			'application/octet-stream'
		)
	};
}

async function aes_decrypt(self: IExecuteFunctions, item: INodeExecutionData, aes_key: string, message: string | Buffer, ivSize: number, tagSize: number, isBinary: boolean = false)
{
	const encrypted_buffer = Buffer.from(message as string, 'base64');
	const contentSize = encrypted_buffer.length - (ivSize + tagSize);
	const content = encrypted_buffer.subarray(0, contentSize);
	const iv = encrypted_buffer.subarray(contentSize, contentSize + ivSize);
	const tag = encrypted_buffer.subarray(contentSize + ivSize, contentSize + ivSize + tagSize);

	const enigma = new Enigma.AES();
	const options: Enigma.AES.Options = {};

	if(aes_key.length > 0)
		options.key = Buffer.from(aes_key, 'base64');
	else
	{
		// eslint-disable-next-line n8n-nodes-base/node-execute-block-wrong-error-thrown
		throw new Error('AES key is required for decryption');
	} 

	const aes = await enigma.init(options);
	const decrypt = await aes.decrypt({ content, iv, tag });

	if(!isBinary)
		item.json.encrypted = decrypt.toString();
	else
	item.binary = {
		data: await self.helpers.prepareBinaryData(
			decrypt,
			'decrypted_file.dat',
			'application/octet-stream'
		)
	};
}

async function rsa_keygen(item: INodeExecutionData)
{
	const key_pair = await Enigma.RSA.create_keypair();

	item.json.public_key = key_pair.public_key.toString('base64');
	item.json.private_key = key_pair.private_key.toString('base64');
}

async function ras_encrypt(item: INodeExecutionData, public_key: string, private_key: string, message: string)
{
	const enigma = new Enigma.RSA();
	const options: Enigma.RSA.Options = {
		keypair: {
			public_key: Buffer.from(public_key, 'base64'),
			private_key: Buffer.from(private_key, 'base64'),
		},
	};
	const rsa = await enigma.init(options);
	const encrypted = await Enigma.RSA.encrypt(message, rsa.keypair.public_key);
	item.json.encrypted = encrypted.toString('base64');
}

async function ras_decrypt(item: INodeExecutionData, public_key: string, private_key: string, message: string)
{
	const enigma = new Enigma.RSA();
	const options: Enigma.RSA.Options = {
		keypair: {
			public_key: Buffer.from(public_key, 'base64'),
			private_key: Buffer.from(private_key, 'base64'),
		},
	};
	const rsa = await enigma.init(options);
	const decrypted = await rsa.decrypt(Buffer.from(message, 'base64'));
	item.json.decrypted = decrypted.toString();
}

async function ecc_keygen(item: INodeExecutionData)
{
	const key_pair = Enigma.ED25519.create_keypair();

	item.json.public_key = key_pair.public_key.toString('base64');
	item.json.private_key = key_pair.private_key.toString('base64');
}

async function ecc_sign(item: INodeExecutionData, public_key: string, private_key: string, message: string)
{
	var options: Enigma.ED25519.Options = {
		keypair: {
			public_key: Buffer.from(public_key, 'base64'),
			private_key: Buffer.from(private_key, 'base64'),
		},
	};
	const ecc = new Enigma.ED25519(options);
	const signature = ecc.sign(message);
	item.json.encrypted = signature.toString('base64');
}

async function ecc_verify(item: INodeExecutionData, public_key: string, message: string, signature: string)
{
	const valid = await Enigma.ED25519.verify(message, Buffer.from(public_key, 'base64'), Buffer.from(signature, 'base64'));
	item.json.valid = valid;
}