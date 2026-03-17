const NmapRunner = require('./utils/nmapRunner');

console.log('Testing target processing:');
console.log('https://etechgs.com ->', NmapRunner.processTarget('https://etechgs.com'));
console.log('http://www.google.com ->', NmapRunner.processTarget('http://www.google.com'));
console.log('google.com ->', NmapRunner.processTarget('google.com'));
console.log('192.168.1.1 ->', NmapRunner.processTarget('192.168.1.1'));
