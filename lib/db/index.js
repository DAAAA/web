var nano = require('nano')('http://localhost:5984');

function create(name) {
    nano.db.create(name, function (err) {
        if (err) {
            console.error(err);
            console.trace(err.stack);
        }
    });
}
exports.create = create;

function destroy(name) {
    nano.db.destroy(name, function (err) {
        if (err) {
            console.error(err);
            console.trace(err.stack);
        }
    });
}
exports.destroy = destroy;
