module.exports = (app, passport) => {

	app.get('/', (req, res) => {
		res.render('index');
	});

	app.get('/login', (req, res) => {
		res.render('login', {
			message: req.flash('loginMessage')
		});
	});

	app.post('/login', passport.authenticate('local-login',{
		successRedirect: '/profile',
		failureRedirect: '/login',
		failureFlash: true
	}));

	app.get('/signup', (req, res) => {
		res.render('signup', {
			message: req.flash('signupMessage')
		});
	});

	app.post('/signup', passport.authenticate('local-signup', {
		successRedirect: '/profile',
		failureRedirect: '/signup',
		failureFlash: true
	} ));

	app.get('/profile', isLoggedIn, (req, res) => {
		res.render('profile', {
			user: req.user
		});
	});
	

	app.get('/cliente', isLoggedIn, (req, res) => {
		res.render('cliente', {
			user: req.user
		});
	});

	app.post('/cliente', passport.authenticate('local-signup', {
		successRedirect: '/cliente',
		failureRedirect: '/error',
		failureFlash: true
	} ));

	app.get('/offset', isLoggedIn, (req, res) => {
		res.render('offset', {
			user: req.user
		});
	});

	app.get('/logout', (req, res) =>{
		req.logout();
		res.redirect('/');
	});

	app.get('/error', isLoggedIn, (req, res) => {
		res.render('error', {
			user: req.user
		});
	});

};

function isLoggedIn(req, res, next) {
	if (req.isAuthenticated()) {
		return next();
	}
	return res.redirect('/');
}



