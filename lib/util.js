var bcrypt = require('bcrypt');
exports.getProps = function getProps(obj, props) {
    var ret = {},
        i, len, current;
        
    for (i = 0, len = props && props.length || 0; i < len; i++) {
        current = props[i];
        ret[current] = obj[current];
    }
    return ret;
};
exports.hashPassword = function hashPassword(input) {
    return bcrypt.hashSync(input, bcrypt.genSaltSync(10));
};
