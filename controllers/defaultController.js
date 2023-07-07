const mysql = require('mysql');
const {connection, pool} = require('../config/config');
const nodemailer = require('nodemailer');
const fs = require('fs');
const {isEmpty} = require('../config/customFunction')
const fileUpload = require('express-fileupload');
const path = require('path');
const multiparty = require('multiparty');
const { json } = require('body-parser');
const util = require('util');
const crypto = require("crypto");
const rand = crypto.randomBytes(4).toString("base64");
const bcrypt = require('bcryptjs');
const {loggedIn, logger} = require('../config/customFunction');




module.exports  = {

    
    login: (req, res, next) => {
            res.render('default/login');
    },
    
    index: (req, res) => {
        const user = req.session.user;
            res.render('default/index',{user});
    },
    
    newMerchants: (req, res) => {
        pool.getConnection((err, connection) =>{
            const merstatus = "Pending";
            if(!err){
                connection.query('SELECT * FROM merchant WHERE status =?', merstatus, (err, merchants) =>{
                    connection.release();
                    if(!err){
                    res.render('default/new-merchants', {merchants: merchants})
                    }else{
                        res.status(500).send('Internal Server Error')
                    }
                })
            
            }
        })
    },
    
    
    disabledMerchants: (req, res) => {
        pool.getConnection((err, connection) =>{
            const merstatus = "Disabled";
            if(!err){
                connection.query('SELECT * FROM merchant WHERE status =?', merstatus, (err, merchants) =>{
                    connection.release();
                    if(!err){
                    res.render('default/disabled-merchants', {merchants: merchants})
                    }else{
                        res.status(500).send('Internal Server Error')
                    }
                })
            
            }
        })
    },
    
    deniedMerchants: (req, res) => {
        pool.getConnection((err, connection) =>{
            const merstatus = "Denied";
            if(!err){
                connection.query('SELECT * FROM merchant WHERE status =?', merstatus, (err, merchants) =>{
                    connection.release();
                    if(!err){
                    res.render('default/denied-merchants', {merchants: merchants})
                    }else{
                        res.status(500).send('Internal Server Error')
                    }
                })
            
            }
        })
    },
    
    allMerchants: (req, res) => {
            pool.getConnection((err, connection) =>{
                const merstatus = "Active";
                if(!err){
                    connection.query('SELECT * FROM merchant WHERE status =?', merstatus, (err, merchants) =>{
                        connection.release();
                        if(!err){
                        res.render('default/all-merchants', {merchants: merchants})
                        }else{
                            res.status(500).send('Internal Server Error')
                        }
                    })
                
                }
            })
    },

    approveMerchant: (req, res) => {

        pool.getConnection((err, connection) =>{
            if(err) throw err;
            const update = {
                status: "Active"
            }
            connection.query('UPDATE merchant_users SET? WHERE merchant_id =?', [update, req.params.id], (err, merchants) => {
                if (!err){
                    connection.query('UPDATE merchant SET? WHERE id =?', [update, req.params.id], (err, success) =>{
                        if (err) throw err;
                        res.redirect('/new-merchants')
                    })
                }
            })
        })

    },

    enableMerchant: (req, res) => {

        pool.getConnection((err, connection) =>{
            if(err) throw err;
            const update = {
                status: "Active"
            }
            connection.query('UPDATE merchant_users SET? WHERE merchant_id =?', [update, req.params.id], (err, merchants) => {
                if (!err){
                    connection.query('UPDATE merchant SET? WHERE id =?', [update, req.params.id], (err, success) =>{
                        if (err) throw err;
                        res.redirect('/disabled-merchants')
                    })
                }
            })
        })

    },

    enabledMerchant: (req, res) => {

        pool.getConnection((err, connection) =>{
            if(err) throw err;
            const update = {
                status: "Active"
            }
            connection.query('UPDATE merchant_users SET? WHERE merchant_id =?', [update, req.params.id], (err, merchants) => {
                if (!err){
                    connection.query('UPDATE merchant SET? WHERE id =?', [update, req.params.id], (err, success) =>{
                        if (err) throw err;
                        res.redirect('/merchant/'+req.params.id)
                    })
                }
            })
        })

    },

    denyMerchant: (req, res) => {

        pool.getConnection((err, connection) =>{
            if(err) throw err;
            const update = {
                status: "Denied"
            }
            
            connection.query('UPDATE merchant SET? WHERE id =?', [update, req.params.id], (err, merchants) => {
                if (!err){
                    connection.query('UPDATE merchant_users SET? WHERE merchant_id =?', [update, req.params.id], (err, success) =>{
                        if (err) throw err;
                        res.redirect('/new-merchants')
                    })
                }
            })
        })

    },


    merchant: (req, res) => {
        
            pool.getConnection((err, connection) =>{
                if(!err){
                    connection.query('SELECT * FROM stores WHERE merchant_id =?', req.params.id, (err, stores) =>{
                        if(!err){
                            connection.query('SELECT * FROM merchant WHERE id =?', req.params.id, (err, mer) => {
                                connection.release();
                                if(!err){
                                    if(mer[0].status == "Disabled"){
                                        const disabled = mer[0];
                                        res.render('default/merchant', {disabled, store: stores, mer:mer[0]})
                                    }else{
                                        const active = mer[0];
                                     res.render('default/merchant', {active, store: stores, mer:mer[0]})
                                    }
                                }else{
                                    res.status(500).send('Internal Server Error')
                                }
                            })
                        }else{
                            res.status(500).send('Internal Server Error')
                        }
                    })
                
                }
            })
    },

    store: (req, res) => {
    
            pool.getConnection((err, connection) =>{
                if(!err){
                    connection.query('SELECT * FROM stores WHERE id =?', [req.params.id], (err, store) =>{
                        connection.release();
                        const noScan = 1;
                        if(!err){
                        res.render('default/store', {store: store[0], noScan})
                        }else{
                            res.status(500).send('Internal Server Error')
                        }
                    })
                
                }
            })
    },

    disableMerchant: (req, res) => {

        pool.getConnection((err, connection) =>{
            if(err) throw err;
            const update = {
                status: "Disabled"
            }
            connection.query('UPDATE merchant_users SET? WHERE merchant_id =?', [update, req.params.id], (err, merchants) => {
                if (!err){
                    connection.query('UPDATE merchant SET? WHERE id =?', [update, req.params.id], (err, success) =>{
                        if (err) throw err;
                        res.redirect('/merchant/'+req.params.id)
                    })
                }
            })
        })

    },

    newStore: (req, res) => {
        res.render('default/create-store');

    },

    createStore: (req, res) => {
        const newStore = {
            name: req.body.name,
            address: req.body.address,
            category: req.body.category,
            no_of_pos: req.body.no_of_pos,
            city: req.body.city,
            province: req.body.province,
            merchant_id: req.session.merchant_id,
            merchant_name: req.session.merchant_name,
            store_id: rand,
            status: req.body.status

        }
        pool.getConnection((err, connection) =>{
            if(err) throw err;
            connection.query('INSERT INTO stores SET?', newStore, (err, saved) => {
                connection.release();
                if (!err) {
                    res.redirect('stores');
                }else{
                    throw err;
                }
            })
        })
    },

    
    editStore: (req, res) => {
        pool.getConnection((err, connection) => {
            if (err) throw err;
            connection.query(`SELECT * from stores WHERE id =?`, [req.params.id], (err, store) => {
                connection.release();
                if (!err){
                    res.render(`default/edit-store`, {store : store[0]});
                }else{
                    throw err;
                }
            })
        })
    },



    updateStore: (req, res) => {
        const data = {
            name: req.body.name,
            address: req.body.address,
            category: req.body.category,
            no_of_pos: req.body.no_of_pos,
            city: req.body.city,
            province: req.body.province,
            merchant_id: req.session.merchant_id,
            merchant_name: req.session.merchant_name,
            status: req.body.status

        }
        pool.getConnection((err, connection) =>{
            if(err) throw err;
            connection.query('UPDATE stores SET? WHERE id =?', [data, req.params.id], (err, saved) => {
                connection.release();
                if (!err) {
                    res.redirect('/stores');
                }else{
                    throw err;
                }
            })
        })
    },

    deleteStore: (req, res) => {
        pool.getConnection((err, connection) => {
            if (err) throw err;

            connection.query('DELETE from stores WHERE id =?', [req.params.id], (err, deleted) => {
                connection.release();
                if (!err){
                    res.redirect('/stores');
                }else{
                    throw err;
                }
            })
        })

    },


    createUser: (req, res) => {
        res.render('default/create-user');
    },

    adminUsers: (req, res) => {
            pool.getConnection((err, connection) =>{
                if(!err){
                    connection.query('SELECT * FROM admin_user', (err, users) =>{
                        connection.release();
                        if(!err){
                        res.render('default/admin-users', {user: users})
                        }else{
                            res.status(500).send('Internal Server Error')
                        }
                    })
                
                }
            })


    },

    merchantUsers: (req, res) => {
            pool.getConnection((err, connection) =>{
                if(!err){
                    connection.query('SELECT * FROM merchant_users', (err, users) =>{
                        connection.release();
                        if(!err){
                        res.render('default/merchant-users', {user: users})
                        }else{
                            res.status(500).send('Internal Server Error')
                        }
                    })
                
                }
            })


    },

    appUsers: (req, res) => {
            pool.getConnection((err, connection) =>{
                if(!err){
                    connection.query('SELECT * FROM app_users', (err, users) =>{
                        connection.release();
                        if(!err){
                        res.render('default/app-users', {user: users})
                        }else{
                            res.status(500).send('Internal Server Error')
                        }
                    })
                
                }
            })


    },

    setupPayment: (req, res) => {
   
        res.render('default/setup-payment');
    },

    paymentHistory: (req, res) => {
   
        res.render('default/payment-history');
    },

    invoice: (req, res) => {
   
        res.render('default/invoice');
    },

    scans: (req, res) => {
      
        res.render('default/scans');
    },


    

    faq: (req, res) => {
      
        res.render('default/faqs');
    },



    registerUser: (req, res) => {

        const errors = [];
        if (!req.body.firstName || !req.body.email || !req.body.lastName || !req.body.status || !req.body.phone){
            const message = 'All fields are mandatory'
            res.render('default/create-user', {message});
        }
        else if (req.body.password !== req.body.comfirmPassword || req.body.password == ""){
            const message = 'Passwords do not match'
            res.render('default/create-user', {message});
        }else{

            pool.getConnection((err, connection) =>{
                if (err) throw err;
                connection.query('SELECT email FROM merchant_users WHERE email =?', [req.body.email], (err, user) => {
                    connection.release()
                    if (err){
                        throw err;
                    }else{
                        const newUser = {
                            first_name: req.body.firstName,
                            last_name: req.body.lastName,
                            email: req.body.email,
                            phone: req.body.phone,
                            password: req.body.password,
                            user_type: 'Admin',
                            merchant_id: req.session.merchant_id,
                            merchant_name: req.session.merchant_name,
                            status: req.body.status
                        };                      
                        bcrypt.genSalt(10, (err, salt) => {
                            bcrypt.hash(newUser.password, salt, (err, hash) => {
                                newUser.password = hash;
    
                                connection.query('INSERT INTO merchant_users SET?', newUser, (err, saved) =>{
                                    if (!err){
                                        res.redirect('users')
                                    }else{
                                        throw err;
                                    }
                                })
                            });
                        });
                    }
                })
            })
        }
        
                
           
    },
    
    deleteUser: (req, res) => {
        pool.getConnection((err, connection) => {
            if (err) throw err;

            connection.query('DELETE from merchant_users WHERE id =?', [req.params.id], (err, deleted) => {
                connection.release();
                if (!err){
                    res.redirect('/users');
                }else{
                    throw err;
                }
            })
        })

    },


    editUser: (req, res) => {
        pool.getConnection((err, connection) => {
            if (err) throw err;
            connection.query(`SELECT * from merchant_users WHERE id =?`, [req.params.id], (err, user) => {
                connection.release();
                if (!err){
                    res.render(`default/edit-user`, {user : user[0]});
                }else{
                    throw err;
                }
            })
        })
    },

    updateUser: (req, res) => {


       
            const data = {
                first_name: req.body.firstName,
                last_name: req.body.lastName,
                email: req.body.email,
                phone: req.body.phone,
                status: req.body.status
            }
        pool.getConnection((err, connection) =>{
            if(err) throw err;
            connection.query('UPDATE merchant_users SET? WHERE id =?', [data, req.params.id], (err, saved) => {
                connection.release();
                if (!err) {
                    res.redirect('/users');
                }else{
                    throw err;
                }
            })
        })
                
           
    },

    
    























    file: (req, res) => {
                
        let filename = '';
        if(!isEmpty(req.files)){
            let file =req.files.cover;
            filename = rand+'-'+file.name;
            let uploadDir1 = './public/uploads/';
    
            file.mv(uploadDir1+filename, (err) => {
                if (err) 
                    throw err;
            })
        }

        const application = {
            first_name: req.body.first_name,
            last_name: req.body.last_name,
            email: req.body.email,
            tel: req.body.tel,
            status: 'Unread',
            position: req.body.position,
            position_id: req.body.position_id, 
            cv: `/uploads/${filename}`
        }
        
            
       pool.getConnection((err, conn) => {
            if(!err){
                conn.query('INSERT INTO applications SET?', application, (err, saved) => {
                    conn.release();
                    if(!err){
                        res.render('default/jobs/submit-success')
                    }else{
                        throw err
                    }
                })
            }
       })
        

    },






}