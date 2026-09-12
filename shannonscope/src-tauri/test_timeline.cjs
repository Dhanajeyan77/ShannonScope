const fs = require('fs');
const path = require('path');

function walk(dir) {
    let results = [];
    let list = fs.readdirSync(dir);
    list.forEach(function(file) {
        file = path.resolve(dir, file);
        let stat = fs.statSync(file);
        if (stat && stat.isDirectory()) {
            results = results.concat(walk(file));
        } else {
            results.push({
                file: file,
                mtime: stat.mtimeMs,
                ctime: stat.ctimeMs,
                atime: stat.atimeMs
            });
        }
    });
    return results;
}

const res = walk('../src');
console.log(`Found ${res.length} files with MAC timestamps!`);
console.log(res[0]);
