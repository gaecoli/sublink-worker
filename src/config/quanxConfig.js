/**
 * Quantumult X Configuration
 * Base configuration template for Quantumult X client
 */

// Remote rule lists are reused from the Surge rule source (2-column Surge rule-set format),
// which Quantumult X cannot read natively; the resource parser converts them on device.
export const QUANX_RESOURCE_PARSER_URL = 'https://fastly.jsdelivr.net/gh/KOP-XIAO/QuantumultX@master/Scripts/resource-parser.js';

export const QUANX_CONFIG = {
	general: {
		'resource_parser_url': QUANX_RESOURCE_PARSER_URL,
		'network_check_url': 'http://www.baidu.com/',
		'server_check_url': 'http://www.gstatic.com/generate_204',
		'server_check_timeout': 3000,
		'dns_exclusion_list': '*.cmpassport.com, *.jegotrip.com.cn, *.icitymobile.mobi, id6.me',
		'excluded_routes': '239.255.255.250/32'
	},
	// [dns] mixes flag-only lines (e.g. no-ipv6) with key=value lines, so keep raw lines
	dns: [
		'no-ipv6',
		'server = 223.5.5.5',
		'server = 119.29.29.29'
	]
};
