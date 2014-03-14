var nano = require('nano')('http://localhost:5984');

function create(name) {
    nano.db.create(name);
}
exports.create = create;

function destroy(name) {
    nano.db.destroy(name);
}
exports.destroy = destroy;
