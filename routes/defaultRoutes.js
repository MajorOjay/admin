const express = require('express');
const router = express.Router();
const defaultController = require('../controllers/defaultController');
const {loggedIn} = require('../config/customFunction');
const bcrypt = require('bcryptjs');


router.all('/*', (req, res, next) => {
    req.app.locals.layout = 'default';

    next();
});


router.route('/')
    .get(loggedIn, defaultController.index);


router.route('/dashboard')
    .get(loggedIn, defaultController.index);

router.route('/new-merchants')
    .get(loggedIn, defaultController.newMerchants);

router.route('/all-merchants')
    .get(loggedIn, defaultController.allMerchants);

router.route('/disabled-merchants')
    .get(loggedIn, defaultController.disabledMerchants);

router.route('/denied-merchants')
    .get(loggedIn, defaultController.deniedMerchants);

router.route('/enable/:id')
    .get(loggedIn, defaultController.enableMerchant)

router.route('/enabled/:id')
    .get(loggedIn, defaultController.enabledMerchant)


router.route('/disable/:id')
.get(loggedIn, defaultController.disableMerchant)


router.route('/merchant/:id')
    .get(loggedIn, defaultController.merchant);

router.route('/store/:id')
    .get(loggedIn, defaultController.store);

    
router.route('/approve/:id')
    .get(loggedIn, defaultController.approveMerchant)  
    
router.route('/deny/:id')
    .get(loggedIn, defaultController.denyMerchant);  
    


router.route('/admin-users')
    .get(loggedIn, defaultController.adminUsers);  

router.route('/app-users')
    .get(loggedIn, defaultController.appUsers)  

router.route('/merchant-users')
    .get(loggedIn, defaultController.merchantUsers)  
    
router.route('/edit-user/:id')
    .get(loggedIn, defaultController.editUser)
    .put(loggedIn, defaultController.updateUser);

router.route('/delete-user/:id')
    .get(loggedIn, defaultController.deleteUser);  

router.route('/setup-payment')
    .get(loggedIn, defaultController.setupPayment)  

router.route('/payment-history')
    .get(loggedIn, defaultController.paymentHistory)  

router.route('/invoice')
    .get(loggedIn, defaultController.invoice)  

router.route('/scans')
    .get(loggedIn, defaultController.scans)  



router.get('/logout', (req, res) => {
    req.session.destroy();
   // req.flash('success', 'You have successfully logged out');
    res.redirect('/auth')
})
 


router.get('/sitemap.xml', (req, res) => {
    res.sendFile('/views/default/sitemap.xml', {root: "."})
})





module.exports = router;
    