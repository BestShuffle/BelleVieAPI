const config = require('./config.js');
const express = require('express');
const app = express();
const cors = require('cors');
const {Pool} = require('pg');

const http = require('http')
const https = require('https')

const jwt = require('jsonwebtoken');
const fs = require('fs');

const nodemailer = require('nodemailer');

const expressJwt = require('express-jwt');
const crypto = require('crypto');

// const spawn = require("child_process").spawn;
const secureRandomPassword = require('secure-random-password');

const multer = require('multer');
const upload = multer();
const type = upload.single('file');
const request = require('request');
const ftp = require('ftp');

//process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

const CONNECTION_STRING = 'postgresql://' + config.BDD_USER + ':' + config.BDD_PASSWORD + '@' +
    config.BDD_HOST + ':' + config.BDD_PORT + '/' + config.BDD_DATABASE;
const sql = new Pool({
    connectionString: CONNECTION_STRING,
    ssl: false
});

const RSA_PUBLIC_KEY = fs.readFileSync(config.API_PATH_JWT_PUBLIC_KEY);
const RSA_PRIVATE_KEY = fs.readFileSync(config.API_PATH_JWT_PRIVATE_KEY);
const CRYPTO_SECRET = fs.readFileSync(config.API_PATH_CRYPTO_SECRET);

const checkIfAuthenticated = expressJwt({
    secret: RSA_PUBLIC_KEY,
    algorithms: ['RS256']
}).unless({
    path: ['/login', '/']
});

/* LOGS DANS FICHIERS
const proc = require('proc');

var writeStream = fs.createWriteStream('./logs/api' + Date.now() + '.log', {
    encoding: 'utf8',
    flags: 'w'
});

process.stdout = require('stream').Writable();
process.stdout._write = function (chunk, encoding, callback) {
    writeStream.write(chunk + "\r\n", encoding, callback);
};

process.stderr = require('stream').Writable();
process.stderr._write = function (chunk, encoding, callback) {
    writeStream.write("ERROR :\r\n" + chunk + "\r\n", encoding, callback);
};
// FIN LOGS */


app.use(function (err, req, res, next) {
    if (err instanceof SyntaxError && err.status === 400) {
        console.error(err);
        return res.sendStatus(400); // Bad request
    }

    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});

// On génère la constante de l'URL de l'API
config.DOLIBARR_URL = config.API_DOLIBARR_SCHEME + '://' + config.API_DOLIBARR_HOST
config.API_DOLIBARR_URL = config.DOLIBARR_URL + config.API_DOLIBARR_PATH

// app.use(upload.array());
app.use(express.json());
app.use(express.urlencoded({extended: false}));
app.use(cors());

const bodyParser = require('body-parser');
app.use(bodyParser.json()); // support json encoded bodies
app.use(bodyParser.urlencoded({extended: true})); // support encoded bodies

module.exports = app;

// Login
app.route(config.API_PATH + '/login').post(login);

app.route(config.API_PATH + '/register').post( register);

// Avec token JWT
app.route(config.API_PATH + '/confirm/:token').get(confirm);
app.route(config.API_PATH + '/forget/password').post(forgetPassword);
app.route(config.API_PATH + '/forget/password/reset').post(resetPassword);

// Account
app.route(config.API_PATH + '/account/infos').get(checkIfAuthenticated, getAccountInfos);
app.route(config.API_PATH + '/account/update').patch(checkIfAuthenticated, updateAccount);
app.route(config.API_PATH + '/account/update/field/:field').patch(checkIfAuthenticated, updateAccountField);

// Pictures
app.route(config.API_PATH + '/pictures/:type/:id').get(getPicture);

// Products
app.route(config.API_PATH + '/categories/:id').get(getCategory);
app.route(config.API_PATH + '/products/:id').get(getProduct);

// Generic modules
app.route(config.API_PATH + '/:module').get(getDolibarr);
app.route(config.API_PATH + '/:module/:id').get(getDolibarr);

// app.route('/api/login/refresh').post(checkIfAuthenticated, refreshToken);

function updateAccountField(req, res) {
    const field = req.params.field;
    const oldValue = req.body.oldValue;
    const newValue = req.body.newValue;
    const decodedReq = req.user;
    const accountId = decodedReq.id;
    if (field === 'password') {
        isPasswordValid(accountId, oldValue, () => {
            updatePassword(req, accountId, newValue, accountId, () => {
                sql.query(`SELECT email FROM "${config.BDD_NAME}".account WHERE id = $1`,
                    [accountId],
                    (error, results) => {
                        if (error) throw error;
                        sendMail('Modification de votre mot de passe',
                            `Bonjour,<br/><br/>Votre mot de passe a été modifié.<br/><br/>Cordialement,<br/>L'équipe ${config.APP_NAME}`,
                            results.rows[0].email,
                            () => {
                                res.send({message: '<span class="green">Mot de passe mis à jour</span>'});
                                postStats(req, {author: accountId, obj: field}, 'COMPTE - Mise à jour de mot de passe',
                                    METHOD_UPDATE);
                            }, () => {
                                res.status(500).send({
                                    message: '<span class="red">Il y a eu une erreur durant le traitement de votre demande, veuillez contacter un administrateur</span>'
                                });
                            });
                    });
            }, () => {
                res.status(500).send({message: '<span class="red">Erreur lors de la mise à jour du mot de passe</span>'});
            });
        }, () => {
            res.status(500).send({message: '<span class="red">Mot de passe incorrect</span>'});
        });
    } else {
        switch (field) {
            case 'description':
            case 'lastName':
            case 'firstName':
            case 'phone':
            case 'mobile':
                strQuery = `UPDATE "${config.BDD_NAME}".account SET ${field} = $1 WHERE email = $2 AND ${field} = $3`;
                break;
        }
        let strQuery;
        sql.query(strQuery,
            [newValue, accountId, oldValue],
            function (error, results) {
                if (error) throw error;
                if (results) {
                    res.status(200).send();
                    postStats(req, {author: accountId, obj: {field, oldValue, newValue}},
                        'UTILISATEUR - Mise à jour d\'informations utilisateur',
                        METHOD_UPDATE);
                }
            });
    }
}

function updatePassword(req, accountId, password, authorId, success, failure) {
    strToSha256(password, function (hashedPassword) {
        sql.query(`UPDATE "${config.BDD_NAME}".account SET password = $1 WHERE id = $2 AND active = true`,
            [hashedPassword, accountId], (error, results) => {
                if (error) throw error;
                if (results) {
                    success();
                    postStats(req, {author: authorId, obj: accountId}, 'COMPTE - Mise à jour de mot de passe',
                        METHOD_UPDATE);
                } else {
                    failure();
                }
            });
    });
}

function register(req, res) {
    let account = req.body.account;
    account.email = account.mail;
    checkIfEmailIsTaken(req, account, undefined, () => {
        strToSha256(account.password, (hashedPassword) => {
            sql.query(`INSERT INTO "${config.BDD_NAME}".account (active, last_name, first_name, society, siret, email, password, phone, mobile)` +
                ' VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id',
                [false, account.lastName, account.firstName, account.society, account.siret, account.email,
                    hashedPassword, account.phone, account.mobile], (error, results) => {
                    if (error) {
                        throw error;
                    }
                    const rows = results.rows;
                    if (rows.length > 0) {
                        account.id = rows[0].id;

                        let url = config.WEBSITE_URL + '/confirm/' + generateBearerToken(
                            {id: account.id, email: account.email},
                            60 * 60 * 24 * 365 * 100
                        );

                        sendMail('Confirmation de votre compte ' + config.APP_NAME,
                            `Bonjour,<br/><br/>Votre compte a bien été créé.<br/><br/>Afin de l'activer, veuillez cliquer <a href="${url}">ICI</a><br/><br/>Cordialement,<br/>L'équipe ${config.APP_NAME}`,
                            account.email,
                            () => {
                                res.send({message: `<span class="green">Votre compte a été créé, un lien de confirmation vous a été envoyé par mail.</span>`});
                                postStats(req, {
                                        author: undefined,
                                        obj: account
                                    }, 'UTILISATEUR - Création d\'un compte',
                                    METHOD_INSERT);
                            }, () => {
                                res.status(500).send({
                                    message: '<span class="red">Il y a eu une erreur durant le traitement de votre demande, veuillez contacter un administrateur</span>'
                                });
                            });
                    }
                });
        });
    }, () => {
        res.status(500).send({message: `<span class="red">L'adresse mail est déjà utilisée</span>`});
    });
}

function updateAccount(req, res) {
    const account = req.body.account;
    const decodedReq = req.user;
    const accountId = decodedReq.id;

    isPasswordValid(account.id, account.password, () => {
        checkIfEmailIsTaken(req, account, accountId, () => {
            sql.query(`UPDATE "${config.BDD_NAME}".account SET first_name = $1, last_name= $2, email = $3, phone = $4, mobile = $5, postal = $6, city = $7, address = $8, address_comp = $9, country = $10 WHERE id = $11`,
                [account.firstName, account.lastName, account.email, account.phone, account.mobile, account.postal, account.city, account.address, account.addressComp, account.country, account.id], (error, results) => {
                    if (error) {
                        throw error;
                    }
                    if (results) {
                        let query;
                        let fields;
                        if (results) {
                            res.send({message: '<span class="green">Données mises à jour</span>'});
                            postStats(req, {author: accountId, obj: account}, 'COMPTE - Mise à jour d\'un compte',
                                METHOD_UPDATE);
                        } else {
                            res.status(500).send({message: '<span class="red">Erreur lors de la mise à jour des données</span>'});
                        }
                    }
                }, () => {
                    res.status(500).send({message: '<span class="red">L\'adresse mail est déjà utilisée</span>'});
                });
        });
    }, () => {
        res.status(500).send({message: '<span class="red">Mot de passe incorrect</span>'});
    });
}

function confirm(req, res) {
    // Récupération des données token décryptées
    try {
        const token = req.params.token;
        const decodedToken = jwt.verify(token, RSA_PUBLIC_KEY);
        const accountId = decodedToken.id;
        const accountEmail = decodedToken.email;

        confirmAccount(accountId, () => {
            sendMail('Activation de votre compte', `Bonjour,<br/><br/>Votre compte a bien été activé.<br/><br/>Cordialement,<br/>L'équipe ${config.APP_NAME}`,
                accountEmail, () => {
                    res.send({
                        message: '<span class="green">Votre compte a été activé</span>'
                    });
                }, () => {
                    res.status(500).send({
                        message: '<span class="red">Il y a eu une erreur durant le traitement de votre demande, veuillez contacter un administrateur</span>'
                    });
                });
        }, () => {
            res.status(500).send({
                message: '<span class="red">Il y a eu une erreur durant le traitement de votre demande, veuillez contacter un administrateur</span>'
            });
        });
    } catch (e) {
        if (e.name === 'TokenExpiredError') {
            res.status(501).send({
                message: '<span class="red">Votre lien de réinitialisation est expiré</span>'
            });
        }
    }
}

function confirmAccount(idAccount, success, failure) {
    sql.query(`UPDATE "${config.BDD_NAME}".account SET active = true WHERE id = $1 AND active = false`,
        [idAccount],
        (error, results) => {
            if (error) throw error;

            if (results) {
                success();
            } else {
                failure();
            }
        });
}

function forgetPassword(req, res) {
    // Récupération des données token décryptées
    const accountEmail = req.body.email;

    sql.query(`SELECT id FROM "${config.BDD_NAME}".account WHERE email = $1`,
        [accountEmail],
        function (error, results, fields) {
            if (error) throw error;
            const rows = results.rows;
            if (rows.length > 0) {
                let accountId = rows[0].id;
                let url = config.WEBSITE_URL + '/forget/' + generateBearerToken(
                    {id: accountId, email: accountEmail},
                    60 * 10
                );

                sendMail('Réinitialisation de mot de passe', `Bonjour,<br/><br/>Pour réinitialiser votre mot de passe veuillez cliquer <a href="${url}">ICI</a><br/>Ce lien est valable 10 minutes à compter de la réception de ce mail.<br/><br/>Cordialement,<br/>L'équipe ${config.APP_NAME}`,
                    accountEmail, () => {
                        res.send({
                            message: '<span class="green">Si un compte lié à cette adresse mail existe, un lien de réinitialisation vous a été envoyé.</span>'
                        });
                    }, () => {
                        res.status(500).send({
                            message: '<span class="red">Il y a eu une erreur durant le traitement de votre demande, veuillez contacter un administrateur</span>'
                        });
                    });
            } else {
                res.status(404).send({
                    message: '<span class="green">Si un compte lié à cette adresse mail existe, un lien de réinitialisation vous a été envoyé.</span>'
                });
            }
        });
}


function resetPassword(req, res) {
    // Récupération des données token décryptées
    try {
        const token = req.body.token;
        const decodedToken = jwt.verify(token, RSA_PUBLIC_KEY);
        const accountId = decodedToken.id;
        const accountEmail = decodedToken.email;
        const accountNewPassword = req.body.password;

        updatePassword(req, accountId, accountNewPassword, undefined, function () {
            sendMail('Modification de votre mot de passe', `Bonjour,<br/><br/>Votre mot de passe a été modifié.<br/><br/>Cordialement,<br/>L'équipe ${config.APP_NAME}`,
                accountEmail, () => {
                    res.send({
                        message: '<span class="green">Votre mot de passe a été mis à jour</span>'
                    });
                }, () => {
                    res.status(500).send({
                        message: '<span class="red">Il y a eu une erreur durant le traitement de votre demande, veuillez contacter un administrateur</span>'
                    });
                });
        });
    } catch (e) {
        if (e.name === 'TokenExpiredError') {
            res.status(501).send({
                message: '<span class="red">Votre lien de réinitialisation est expiré</span>'
            });
        }
    }
}

function isPasswordValid(id, password, success, failure) {
    sql.query(`SELECT password FROM "${config.BDD_NAME}".account WHERE id = $1`,
        [id],
        function (error, results, fields) {
            if (error) throw error;
            let rows = results.rows;
            if (rows.length > 0) {
                let hash = rows[0].password;
                verifyPassword(password, hash, function (isValid) {
                    if (isValid) {
                        success();
                    } else {
                        failure();
                    }
                });
            } else {
                failure();
            }
        });
}

function verifyPassword(password, hash, callback) {
    strToSha256(password, (hashedPassword) => {
        callback(hashedPassword === hash);
    });
}

function checkIfEmailIsTaken(req, account, accountId, success, failure) {
    sql.query(`SELECT id FROM "${config.BDD_NAME}".account WHERE email = $1`,
        [account.email],
        function (error, results, fields) {
            if (error) throw error;
            let rows = results.rows;
            if (rows && rows.length !== 0 && rows[0] && rows[0].id !== account.id) {
                failure();
                postStats(req, {author: accountId, obj: account},
                    'COMPTE - L\'adresse mail est déjà utilisée', METHOD_SELECT);
            } else {
                success();
            }
        });
}

function getAccountInfos(req, res) {
    // Récupération des données token décryptées
    const decodedReq = req.user;
    const idAccount = decodedReq.id;

    sql.query('SELECT id, active, first_name, last_name, email, postal, city, country, address, address_comp, phone, mobile, society, siret' +
        ` FROM "${config.BDD_NAME}".account` +
        ' WHERE id = $1 AND active = true',
        [idAccount],
        (error, results) => {
            if (error) throw error;

            let rows = results.rows;
            if (rows.length > 0) {
                let account = rows[0];
                account.firstName = account.first_name;
                account.lastName = account.last_name;
                account.addressComp = account.address_comp;
                res.send(account);
                postStats(req, {
                        author: idAccount,
                        obj: account
                    }, 'UTILISATEUR - Récupération d\'informations utilisateur',
                    METHOD_SELECT);
            }
        });
}

function login(req, res) {
    const data = {
        id: req.body.id,
        password: req.body.password
    }
    validateLogin(data.id, data.password,
        function (idAccount) {
            const jwtBearerToken = generateBearerToken({
                id: idAccount
            }, 60 * 60 * 24);
            res.cookie("SESSIONID", jwtBearerToken, {httpOnly: true, secure: true});
            res.status(200).json({
                token: jwtBearerToken,
                message: '<span class="green">Vous êtes connecté</span>'
            }).send();
            postStats(req, {author: undefined, obj: data},
                'UTILISATEUR - Connexion utilisateur',
                METHOD_LOGIN);
        }, function () {
            // Unauthorized
            res.status(401).send({message: '<span class="red">Nom de compte ou mot de passe incorrect</span>'});
        });
}


function validateLogin(email, password, success, failure) {
    strToSha256(password, (hash) => {
        sql.query(`SELECT id, password FROM "${config.BDD_NAME}".account WHERE active = true AND email = $1 AND password = $2`,
            [email, hash], (error, results) => {
                if (error) throw error;
                let rows = results.rows;
                if (rows.length > 0) {
                    success(rows[0].id);
                } else {
                    failure();
                }
            });
    });
}

function strToSha256(str, next) {
    const hash = crypto.createHmac('sha256', CRYPTO_SECRET)
        .update(str)
        .digest('hex');
    if (next) {
        next(hash);
    }
}

function generateBearerToken(options, expires) {
    // Connecté 24h
    return jwt.sign(options, RSA_PRIVATE_KEY, {
        algorithm: 'RS256',
        issuer: 'urn:issuer',
        expiresIn: expires,
        subject: config.APP_NAME + 'Login'
    });
}


function getPicture(req, res) {
    const type = req.params.type;
    const id = req.params.id;

    if (type && id) {
        let url = config.API_DOLIBARR_PATH + config.API_DOLIBARR_DOCUMENTS_URL;
        // Mise en place des types / id
        if (type === config.PICTURE_TYPE_CATEGORY) {
            url = url.replace(/:module/g, type).replace(/:file/g, id + '/0/' + id + '/photos/slider.jpg');
        } else {
            url = url.replace(/:module/g, type).replace(/:file/g, id + '/picture.jpg');
        }

        sendDoliGet(url, (dolRes, body) => {
            res.send({data: body.content});
        });
    } else {
        res.status(500).send();
    }
}

function getDolibarr(req, res) {
    let module = req.params.module;
    switch (module) {
        case 'collections':
            module = 'categories';
            break;
    }
    const id = req.params.id;

    const url = config.API_DOLIBARR_PATH + '/' + module + (id ? '/' + id + '/objects?type=product' : '');
    sendDoliGet(url, (dolRes, body) => {
        res.status(dolRes.statusCode).send(body);
    });
}

function getCategory(req, res) {
    const id = req.params.id;

    let result;
    let url = config.API_DOLIBARR_PATH + '/categories/' + id;
    sendDoliGet(url, (dolRes, body) => {
        result = body;
        url = config.API_DOLIBARR_PATH + '/categories/' + id + '/objects?type=product';
        sendDoliGet(url, (dolRes, bodyProducts) => {
            result.products = bodyProducts;
            res.status(dolRes.statusCode).send(result);
        });
    });
}

function getProduct(req, res) {
    const id = req.params.id;
    let url = config.API_DOLIBARR_PATH + '/products/' + id;
    sendDoliGet(url, (dolRes, body) => {
        res.status(dolRes.statusCode).send(body);
    });
}

function sendDoliGet(path, next) {
    const options = {
        hostname: config.API_DOLIBARR_HOST,
        port: 80,
        path: path,
        headers: {
            // Accept: 'application/json',
            DOLAPIKEY: config.API_DOLIBARR_KEY,
        },
        agent: false
    };

    http.get(options, (res) => {
        res.setEncoding('utf8');
        let body = '';
        res.on('data', function (chunk) {
            body += chunk;
        });
        res.on('end', function () {
            let resBody = body;
            try {
                resBody = JSON.parse(resBody);
            } finally {
                next(res, resBody);
            }
        });
    });
}


function sendDoliPost(path, data, next) {
    const options = {
        host: config.API_DOLIBARR_HOST,
        port: '80',
        path: path,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': JSON.stringify(data).length,
            DOLAPIKEY: config.API_DOLIBARR_KEY,
        }
    };

    // Set up the request
    const postReq = http.request(options, function (res) {
        res.setEncoding('utf8');
        let body = '';
        res.on('data', function (chunk) {
            body += chunk;
        });
        res.on('end', function () {
            let resBody = body;
            try {
                resBody = JSON.parse(resBody)
            } catch {
            } finally {
                next(res, resBody);
            }
        });
    });

    // post the data
    postReq.write(JSON.stringify(data));
    postReq.end();
}

function sendMail(subject, content, dest, success, failure) {
    var transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: config.MAIL_USER,
            pass: config.MAIL_PASSWORD
        }
    });

    var mailOptions = {
        from: `${config.MAIL_NAME} <${config.MAIL_USER}>`,
        to: dest,
        subject: subject,
        html: content
    };

    transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
            if (failure) {
                failure();
            }
        } else if (success) {
            success();
        }
        // });
    }, () => {
        if (failure) {
            failure();
        }
    });
}


const METHOD_LOGIN = 'LOGIN';
const METHOD_SELECT = 'SELECT';
const METHOD_DELETE = 'INSERT';
const METHOD_DOWNLOAD = 'DOWNLOAD';
const METHOD_INSERT = 'DELETE';
const METHOD_UPDATE = 'UPDATE';

function postStats(req, data, desc, method) {
    // let stat = {};
    // stat.data = data;
    // stat.specs = {};
    // stat.specs.date = new Date();
    // stat.specs.url = req.originalUrl;
    // stat.specs.desc = desc;
    // stat.specs.method = method;
    //
    // request({ url: 'https://185.116.106.69:5555/api/stats', method: "POST", json: stat });
}
