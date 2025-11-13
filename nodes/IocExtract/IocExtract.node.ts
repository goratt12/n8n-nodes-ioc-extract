import type {
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
} from 'n8n-workflow';
import { NodeConnectionTypes, NodeOperationError } from 'n8n-workflow';

interface IOCResult {
	hashes: {
		md5s: string[];
		sha1s: string[];
		sha256s: string[];
	};
	networks: {
		ipv4s: string[];
		ipv6s: string[];
		urls: string[];
		domains: string[];
		emails: string[];
	};
}

export class IocExtract implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'IOC Extract',
		name: 'iocExtract',
		icon: { light: 'file:IocExtract.svg', dark: 'file:IocExtract.dark.svg' },
		group: ['transform'],
		version: 1,
		description: 'Extract Indicators of Compromise (IOCs) from text',
		defaults: {
			name: 'IOC Extract',
		},
		inputs: [NodeConnectionTypes.Main],
		outputs: [NodeConnectionTypes.Main],
		usableAsTool: true,
		properties: [
			{
				displayName: 'Input Text',
				name: 'inputText',
				type: 'string',
				default: '',
				placeholder: 'Enter text containing IOCs to extract...',
				description: 'The text from which to extract Indicators of Compromise',
				required: true,
			},
			{
				displayName: 'Output Mode',
				name: 'outputMode',
				type: 'options',
				options: [
					{
						name: 'Single Item',
						value: 'single',
						description: 'Output all IOCs in a single item',
					},
					{
						name: 'Each IOC as Item',
						value: 'individual',
						description: 'Output each IOC as a separate item with type attribute',
					},
				],
				default: 'single',
				description: 'Choose how to output the extracted IOCs',
			},
			{
				displayName: 'Refang Input',
				name: 'refangInput',
				type: 'boolean',
				default: false,
				description:
					'Whether to refang defanged IOCs in input text before extraction (e.g., example[.]com → example.com)',
			},
			{
				displayName: 'Defang Output',
				name: 'defangOutput',
				type: 'boolean',
				default: false,
				description:
					'Whether to defang extracted IOCs in the output (e.g., example.com → example[.]com)',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const outputItems: INodeExecutionData[] = [];

		// Refang function: Convert defanged IOCs to normal format
		const refang = (text: string): string => {
			return text
				.replace(/\[\.\]/g, '.')
				.replace(/\(\.\)/g, '.')
				.replace(/\[@\]/g, '@')
				.replace(/\[:\/\/\]/g, '://')
				.replace(/hxxp/gi, 'http')
				.replace(/hxxps/gi, 'https')
				.replace(/\[dot\]/gi, '.')
				.replace(/\(dot\)/gi, '.')
				.replace(/\[at\]/gi, '@')
				.replace(/\(at\)/gi, '@')
				.replace(/\[([0-9a-zA-Z])\]/g, '$1') // Handle bracketed single characters/numbers like [1]
				.replace(/\(([0-9a-zA-Z])\)/g, '$1'); // Handle parenthesized single characters/numbers like (1)
		};

		// Defang function: Convert normal IOCs to defanged format
		const defang = (text: string): string => {
			return text
				.replace(/\./g, '[.]')
				.replace(/@/g, '[@]')
				.replace(/:\/\//g, '[://]');
		};

		// Extract MD5 hashes (32 hex characters)
		const extractMD5 = (text: string): string[] => {
			const regex = /\b[a-fA-F0-9]{32}\b/g;
			const matches = text.match(regex) || [];
			return [...new Set(matches)];
		};

		// Extract SHA1 hashes (40 hex characters)
		const extractSHA1 = (text: string): string[] => {
			const regex = /\b[a-fA-F0-9]{40}\b/g;
			const matches = text.match(regex) || [];
			return [...new Set(matches)];
		};

		// Extract SHA256 hashes (64 hex characters)
		const extractSHA256 = (text: string): string[] => {
			const regex = /\b[a-fA-F0-9]{64}\b/g;
			const matches = text.match(regex) || [];
			return [...new Set(matches)];
		};

		// Extract IPv4 addresses
		const extractIPv4 = (text: string): string[] => {
			const regex =
				/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
			const matches = text.match(regex) || [];
			return [...new Set(matches)];
		};

		// Extract IPv6 addresses (including compressed notation)
		const extractIPv6 = (text: string): string[] => {
			// IPv6 regex pattern covering various formats including compressed notation
			const regex =
				/(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?::[0-9a-fA-F]{1,4}){1,7}|::)/g;
			const matches = text.match(regex) || [];
			return [...new Set(matches)];
		};

		// Extract URLs (HTTP/HTTPS)
		const extractURLs = (text: string): string[] => {
			const regex =
				/\bhttps?:\/\/(?:[-\w.])+(?::[0-9]+)?(?:\/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?/gi;
			const matches = text.match(regex) || [];
			return [...new Set(matches)];
		};

		// Extract email addresses
		const extractEmails = (text: string): string[] => {
			const regex = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
			const matches = text.match(regex) || [];
			return [...new Set(matches)];
		};

		// Extract domains (excluding those in URLs and emails)
		const extractDomains = (text: string, urls: string[], emails: string[]): string[] => {
			// Remove URLs and emails from text to avoid duplicates
			let cleanText = text;
			urls.forEach((url) => {
				cleanText = cleanText.replace(url, '');
			});
			emails.forEach((email) => {
				cleanText = cleanText.replace(email, '');
			});

			// Extract domain names
			const regex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
			const matches = cleanText.match(regex) || [];
			return [...new Set(matches)];
		};

		// Main extraction function
		const extractIOCs = (text: string, shouldRefangInput: boolean, shouldDefangOutput: boolean): IOCResult => {
			// Refang input if needed
			const processedText = shouldRefangInput ? refang(text) : text;

			// Extract all IOCs
			const md5s = extractMD5(processedText);
			const sha1s = extractSHA1(processedText);
			const sha256s = extractSHA256(processedText);
			const ipv4s = extractIPv4(processedText);
			const ipv6s = extractIPv6(processedText);
			const urls = extractURLs(processedText);
			const emails = extractEmails(processedText);
			const domains = extractDomains(processedText, urls, emails);

			// Defang output if needed
			const defangArray = (arr: string[]): string[] => {
				return shouldDefangOutput ? arr.map((item) => defang(item)) : arr;
			};

			return {
				hashes: {
					md5s: defangArray(md5s),
					sha1s: defangArray(sha1s),
					sha256s: defangArray(sha256s),
				},
				networks: {
					ipv4s: defangArray(ipv4s),
					ipv6s: defangArray(ipv6s),
					urls: defangArray(urls),
					domains: defangArray(domains),
					emails: defangArray(emails),
				},
			};
		};

		// Helper function to convert plural to singular
		const toSingular = (word: string): string => {
			// Handle specific mappings
			const singularMap: Record<string, string> = {
				hashes: 'hash',
				networks: 'network',
				md5s: 'md5',
				sha1s: 'sha1',
				sha256s: 'sha256',
				ipv4s: 'ipv4',
				ipv6s: 'ipv6',
				urls: 'url',
				domains: 'domain',
				emails: 'email',
			};

			return singularMap[word] || word.replace(/s$/, '');
		};

		// Helper function to flatten IOC structure and create individual items
		const createIndividualItems = (
			iocs: IOCResult,
			baseItem: INodeExecutionData,
		): INodeExecutionData[] => {
			const individualItems: INodeExecutionData[] = [];

			// Traverse the nested IOC structure
			for (const [category, categoryData] of Object.entries(iocs)) {
				if (typeof categoryData === 'object' && categoryData !== null) {
					for (const [type, values] of Object.entries(categoryData)) {
						if (Array.isArray(values)) {
							for (const value of values) {
								individualItems.push({
									json: {
										value,
										type: toSingular(type),
										category: toSingular(category),
									},
									pairedItem: baseItem.pairedItem,
								});
							}
						}
					}
				}
			}

			return individualItems;
		};

		// Iterates over all input items and extract IOCs from the input text
		for (let itemIndex = 0; itemIndex < items.length; itemIndex++) {
			try {
				const inputText = this.getNodeParameter('inputText', itemIndex, '') as string;
				const outputMode = this.getNodeParameter('outputMode', itemIndex, 'single') as string;
				const shouldRefangInput = this.getNodeParameter('refangInput', itemIndex, false) as boolean;
				const shouldDefangOutput = this.getNodeParameter('defangOutput', itemIndex, false) as boolean;
				const item = items[itemIndex];

				// Extract IOCs from the input text
				const iocs = extractIOCs(inputText, shouldRefangInput, shouldDefangOutput);

				if (outputMode === 'individual') {
					// Create individual items for each IOC
					const individualItems = createIndividualItems(iocs, item);
					outputItems.push(...individualItems);
				} else {
					// Single item mode: Add the extracted IOCs to the output
					item.json.iocs = iocs;
					outputItems.push(item);
				}
			} catch (error) {
				// Handle errors gracefully
				if (this.continueOnFail()) {
					outputItems.push({
						json: this.getInputData(itemIndex)[0].json,
						error,
						pairedItem: itemIndex,
					});
				} else {
					// Adding `itemIndex` allows other workflows to handle this error
					if (error.context) {
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

		return [outputItems];
	}
}
