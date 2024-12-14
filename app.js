const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const axios = require('axios');
const cookieParser = require('cookie-parser');
const path = require('path');

// Set EJS as the view engine
app.set('view engine', 'ejs');
app.set('views', 'views');

app.use(express.static('public'))
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

const sanitizeUserInput = (keyword)=> keyword.replace(/[\\$<>{}.*!&|:+]/g, "")
const sanitizeEmail = (keyword)=> keyword.replace(/[\\$<>{}*!&|:+]/g, "")

app.use((req, res, next)=> {
  req.username = null;
  next();
})

function formatISBN(isbn) {
  // Remove any existing hyphens or spaces
  isbn = isbn.replace(/[-\s]/g, '');


  if (isbn.length === 13) {
    return `${isbn.slice(0, 3)}-${isbn.slice(3, 6)}-${isbn.slice(6, 12)}-${isbn.slice(12)}`;
} else if (isbn.length === 10) {
    return `${isbn.slice(0, 1)}-${isbn.slice(1, 6)}-${isbn.slice(6, 9)}-${isbn.slice(9)}`;
}

  return isbn; // Return unformatted if not valid
}

const checkLoginMiddleware = (req, res, next) => {
  // Retrieve the JWT from cookies
  const jwtToken = req.cookies['jwt-token'];
  const identityToken = req.cookies['identity'];

  // If no token is found, redirect to login
  if (!jwtToken && !identityToken) {
    return res.redirect('/login');
  }

  try {
    // Verify the JWT using the secret key
    let decoded = jwt.verify(jwtToken, process.env.KEY);
    //console.log('Decoded: ',decoded); // Log the decoded token for debugging

    // Attach the username to the request object
    req.username = decoded.username;
    //console.log('username in checkLoginMiddleware ', req.username);
    // Proceed to the next middleware or route handler

    // Verify the JWT using the secret key
    decoded = jwt.verify(identityToken, process.env.KEY);
    //console.log('Decoded: ',decoded); // Log the decoded token for debugging

    // Attach the username to the request object
    req.identity = decoded.identity;
    //console.log('identity in checkLoginMiddleware ', req.identity);
    
    next();
  } catch (error) {
    // Handle errors related to token verification
    if (error.name === 'JsonWebTokenError' && error.message.includes('expired')) {
      //console.log('JWT token expired!');
      res.redirect('/logout'); // Redirect to logout if token is expired
    } else {
      //console.log('Cannot find legal jwt token! ', error.message);
      res.redirect('/logout'); // Redirect for other JWT errors
    }
  }
}

const checkIdentityMiddleware = (req, res, next) => {
  // Retrieve the JWT from cookies
  const identityToken = req.cookies['identity'];

  // If no token is found, redirect to login
  if (!identityToken) {
    return res.redirect('/login');
  }

  try {
    // Verify the JWT using the secret key
    const decoded = jwt.verify(identityToken, process.env.KEY);
    //console.log('Decoded: ',decoded); // Log the decoded token for debugging

    // Attach the username to the request object
    req.identity = decoded.identity;
    //console.log('identity in checkLoginMiddleware ', req.identity);
    // Proceed to the next middleware or route handler

    if(req.identity !== 'staff') {
      res.redirect('/');
    } else {
      next();
    }

  } catch (error) {
    // Handle errors related to token verification
    if (error.name === 'JsonWebTokenError' && error.message.includes('expired')) {
      //console.log('JWT token expired!');
      res.redirect('/logout'); // Redirect to logout if token is expired
    } else {
      //console.log('Cannot find legal jwt token! ', error.message);
      res.redirect('/logout'); // Redirect for other JWT errors
    }
  }

}

app.get('/', checkLoginMiddleware, async (req, res)=> {
  try{
    const response = await axios.get(`${process.env.API_URL}bookGet`)
    
    res.render('index', {username: req.username, data: response.data.Books});
  } catch (error) {
    console.log(error);
    res.status(500).json({error: error.message});
  }
  
})

// Login page
app.get('/login', (req, res)=> {
  res.render('login', {username: req.username, error_code: null, message: null});
}) 

// user login
app.post('/login', async (req, res)=> {
  try {

      let { username, password, identity } = req.body

      username = sanitizeUserInput(username).trim();
      password = sanitizeUserInput(password).trim();

      const response = await axios.post(`${process.env.API_URL}login`, {
          table: identity,
          username: username,
          password: password    
      }, {
        headers: {
        'Content-Type': 'application/json'
      }
      })

      if(response.status === 200) {
      
        const token = jwt.sign( //jwt-token
        {username: username},
        process.env.KEY, 
        { expiresIn: 300 } // 3 minutes
      )

      const identityToken = jwt.sign( //identity-token
        {identity: identity},
        process.env.KEY, 
        { expiresIn: 300 } // 3 minutes
      )

      res.cookie('jwt-token', token, {
        httpOnly: true
        //secure: true //https
      })

      res.cookie('identity', identityToken, {
        httpOnly: true
        //secure: true //https
      })
      }
      
      if(identity === 'staff') {
        res.redirect('/staff');
      } else {
        res.redirect('/');
      }
      
  } catch (error) {
    if(error.response && error.response.status === 401) {
      res.status(401).render('login' ,{error_code: '401', message: 'Username or password incorrect!', username: req.username});
    } else if (error.response && error.response.status === 404) {
      res.status(404).render('login' ,{error_code: '404', message: 'User not found!', username: req.username});
    } else {
      res.status(500).render('login' ,{error_code: '500', message: 'Internal Server Error', username: req.username});
    }
  }
})

app.get('/profile', checkLoginMiddleware , (req, res)=> {
  res.render('profile', {username: req.username});
}) 

app.post('/password-change', checkLoginMiddleware, async (req, res)=> {
  try {
    let { password, newpassword } = req.body

      const username = sanitizeUserInput(req.username).trim();
      password = sanitizeUserInput(password).trim();
      newpassword = sanitizeUserInput(newpassword).trim();

      const response = await axios.patch(`${process.env.API_URL}changePassword`, {
          username: username,
          password: password,
          new_password: newpassword,
          table: req.identity
        
      }, {
        headers: {
        'Content-Type': 'application/json'
      }
      })

      if(response.status === 200) {
        res.redirect('/logout');
      }
      
        

  } catch (error) {
    //res.status(500).render('error' ,{error_code: '500', message: error.message, username: req.username});

    if(error.response && error.response.status === 400) {
      res.status(400).render('error' ,{error_code: '400', message: error.response.data.message, username: req.username});

    } else if (error.response && error.response.status === 404) {
      res.status(404).render('error' ,{error_code: '404', message: error.response.data.message, username: req.username});

    } else if (error.response && error.response.status === 401 && error.response.data.message === 'The password is not correct!') {
      res.status(401).render('error' ,{error_code: '401', message: error.response.data.message, username: req.username});

    } else {
      res.status(500).render('error' ,{error_code: '500', message: error.response.data.message, username: req.username});
    }
  }
}) 

app.get('/logout', (req, res)=> {
  res.clearCookie('jwt-token');
  res.clearCookie('identity');
  res.redirect('login');
})


// Register
app.get('/register', (req, res)=> {
  res.render('register', {username: req.username});
}) 

app.post('/register', async (req, res)=> {
  try {

    let { email, username, password } = req.body
    email = sanitizeEmail(email).trim();
    username = sanitizeUserInput(username).trim();
    password = sanitizeUserInput(password).trim();

    const response = await axios.post(`${process.env.API_URL}register`, {
        email: email,
        username: username,
        password: password
      
    }, {
      headers: {
      'Content-Type': 'application/json'
    }
    })

    if(response.status === 200) { //create user success
      res.redirect('/login');
    }

  } catch (error) {
    if(error.response && error.response.status === 400) {
      res.status(400).render('error' ,{error_code: '400', message: 'Not inputed all the required field', username: req.username});
    } else if (error.response && error.response.status === 409) {
      res.status(409).render('error' ,{error_code: '409', message: 'User already exist!', username: req.username});
    } else {
      res.status(500).render('error' ,{error_code: '500', message: 'Internal Server Error', username: req.username});
    }
  }
})
// End of Register


// Search
app.get('/Search', checkLoginMiddleware, async (req, res) => {
  try {
    if(req.query.keyword !== undefined) {
      const response = await axios.get(`${process.env.API_URL}Search/?keyword=${req.query.keyword}`);
      res.render('postDetail', {
        data: response.data.data,
        username: req.username,
        identity: req.identity
    })
    } else {
      res.render('Search' ,{username: req.username, identity: req.identity});
    }
  } catch (error) {
    res.status(500).json({message: 'Internal Server Error'})
  }
})
// End of Search


// Staff page
// Index
app.get('/staff', checkLoginMiddleware, checkIdentityMiddleware, async (req, res)=> {
  try{
    const response = await axios.get(`${process.env.API_URL}bookGet`)
    
    res.render('staff', {username: req.username, identity: req.identity, data: response.data.Books});
  } catch (error) {
    console.log(error);
    res.status(500).json({error: error.message});
  }
})

app.get('/staff/getbook/:id', checkLoginMiddleware, checkIdentityMiddleware, async (req, res)=> {
  try{
    const bookid = req.params.id;

    const response = await axios.get(`${process.env.API_URL}bookGet/${bookid}`)
    res.render('bookDetail', {username: req.username, data: response.data.Book});
  } catch (error) {
    console.log(error);
    res.status(500).json({error: error.message});
  }
})

// Create
app.get('/create', checkLoginMiddleware, checkIdentityMiddleware, async (req, res)=> {
  try{
    if(req.identity !== 'staff') {
      throw new Error('Forbidden');
    }
    res.render('create', {username: req.username});
  } catch (error) {
    console.log(error);
    res.status(500).json({error: error.message});
  }
})

app.post('/create', checkIdentityMiddleware, async (req, res)=> {
  try{
    if(req.identity !== 'staff') {
      throw new Error('Forbidden');
    }

    const { title, author, ISBN, publisher, publishyear} = req.body;

    const formattedISBN = formatISBN(ISBN);

    const response = await axios.post(`${process.env.API_URL}bookCreate`, {
        title: title,
        author: author,
        ISBN: formattedISBN,
        publisher: publisher,
        year_published: publishyear
      
    }, {
      headers: {
      'Content-Type': 'application/json'
    }
    })

    if(response.status === 201) {
      res.redirect('/create');
    } else {
      res.status(500).render('error' ,{error_code: '500', message: 'Internal Server Error', username: req.username});
    }

  } catch (error) {
    if(error.response && error.response.status === 400) {
      res.status(400).render('error' ,{error_code: '400', message: error.response.data.message, username: req.username});
    } else {
      res.status(500).render('error' ,{error_code: '500', message: 'Internal Server Error', username: req.username});
    }
  }
})

// Delete
app.post('/staff/delete', checkLoginMiddleware, checkIdentityMiddleware, async (req, res)=> {
  try{
    const { id } = req.body;
    
    const response = await axios.delete(`${process.env.API_URL}bookDelete/${id}`)

    if(response.status === 200) {
      res.redirect('/staff')
    } else {
      res.status(500).render('error' ,{error_code: '500', message: 'Internal Server Error', username: req.username});
    }

  } catch (error) {
    console.log(error);
    res.status(500).json({error: error.message});
  }
})

// Update
app.post('/staff/update', checkLoginMiddleware, checkIdentityMiddleware, async (req, res)=> {
  try{
    const { title, author, ISBN, publisher, publishyear, available , id } = req.body;

    const formattedISBN = formatISBN(ISBN);

    const response = await axios.patch(`${process.env.API_URL}bookUpdate/${id}`, {
        ...(title && { title: title }),
        ...(author && { author: author }),
        ...(formattedISBN && { ISBN: formattedISBN }),
        ...(publisher && { publisher: publisher }),
        ...(publishyear && { year_published: publishyear }),
        ...(available && { is_available: available }),
      
    }, {
      headers: {
      'Content-Type': 'application/json'
    }
    })
    
    if(response.status === 200) {
      res.redirect('/staff')
    } else {
      res.status(500).render('error' ,{error_code: '500', message: 'Internal Server Error', username: req.username});
    }

  } catch (error) {
    console.log(error);
    res.status(500).json({error: error.message});
  }
})

// End of Staff

// Admin

app.get('/admin', checkLoginMiddleware, (req, res)=> {
  res.render('admin' ,{error_code: null, message: null, username: req.username});
})

app.get('/admin/login', (req, res)=> {
  res.render('admin-login' ,{error_code: null, message: null, username: req.username});
})

app.post('/admin/login', async (req, res)=> {
  try {

      let { username, password} = req.body

      username = sanitizeUserInput(username).trim();
      password = sanitizeUserInput(password).trim();

      const response = await axios.post(`${process.env.API_URL}login`, {
          table: 'admin',
          username: username,
          password: password
      }, {
        headers: {
        'Content-Type': 'application/json'
      }
      })

      if(response.status === 200) {
      
        const token = jwt.sign( //jwt-token
        {username: username},
        process.env.KEY, 
        { expiresIn: 300 } // 3 minutes
      )

      const identityToken = jwt.sign( //identity-token
        {identity: 'admin'},
        process.env.KEY, 
        { expiresIn: 300 } // 5 minutes
      )

      res.cookie('jwt-token', token, {
        httpOnly: true
        //secure: true //https
      })

      res.cookie('identity', identityToken, {
        httpOnly: true
        //secure: true //https
      })
      }
      
      res.redirect('/admin');
      
  } catch (error) {
    if(error.response && error.response.status === 401) {
      res.status(401).render('admin-login' ,{error_code: '401', message: 'Username or password incorrect!', username: req.username});
    } else if (error.response && error.response.status === 404) {
      res.status(404).render('admin-login' ,{error_code: '404', message: 'User not found!', username: req.username});
    } else {
      res.status(500).render('admin-login' ,{error_code: '500', message: error.message, username: req.username});
    }
  }
})

// Insert a new staff
app.get('/admin/add', checkLoginMiddleware, (req, res)=> {
  res.render('insert-staff' ,{error_code: null, message: null, username: req.username});
})

app.post('/admin/add', async (req, res)=> {
  try {

    const { username, fullname ,password} = req.body

    const response = await axios.post(`${process.env.API_URL}insertstaff`, {
        username: username,
        fullname: fullname,
        password: password
    }, {
      headers: {
      'Content-Type': 'application/json'
    }
    })

    if(response.status === 200) {
      res.render('insert-staff' ,{error_code: null, message: 'New staff has been added', username: req.username});
    }
    
  } catch (error) {
    if(error.response && error.response.status === 400) {
      res.status(400).render('error' ,{error_code: '400', message: error.response.data.message, username: req.username});
    } else if (error.response && error.response.status === 409) {
      res.status(409).render('error' ,{error_code: '409', message: error.response.data.message, username: req.username});
    } else {
      res.status(500).render('error' ,{error_code: '500', message: 'Internal Server Error', username: req.username});
    }
  }
  
})

app.get('/admin/delete', checkLoginMiddleware, (req, res)=> {
  res.render('delete-staff' ,{error_code: null, message: null, username: req.username});
})

app.post('/admin/delete', async (req, res)=> {
  try {

    const { username, fullname } = req.body

    const response = await axios.delete(`${process.env.API_URL}deletestaff`, {
      data: {
        username: username,
        fullname: fullname
      },
    }, {
      headers: {
      'Content-Type': 'application/json'
    }
    })

    if(response.status === 200) {

      res.render('delete-staff' ,{error_code: null, message: response.data.message, username: req.username});
    }
  } catch (error) {
    if(error.response && error.response.status === 400) {
      res.status(400).render('error' ,{error_code: '400', message: error.response.data.message, username: req.username});
    } else if (error.response && error.response.status === 409) {
      res.status(409).render('error' ,{error_code: '409', message: error.response.data.message, username: req.username});
    } else {
      res.status(500).render('error' ,{error_code: '500', message: error.message, username: req.username});
    }
  }
})

app.get('/admin/change', checkLoginMiddleware, (req, res)=> {
  res.render('admin-change-password' ,{error_code: null, message: null, username: req.username});
})

app.post('/admin/change', async (req, res)=> {
  try {

    const { username, fullname, new_password } = req.body

    const response = await axios.patch(`${process.env.API_URL}passwordchange`, {
      data: {
        username: username,
        fullname: fullname,
        new_password: new_password
      },
    }, {
      headers: {
      'Content-Type': 'application/json'
    }
    })

    if(response.status === 200) {

      res.render('admin-change-password' ,{error_code: null, message: response.data.message, username: req.username});
    }
  } catch (error) {
    if(error.response && error.response.status === 400) {
      res.status(400).render('error' ,{error_code: '400', message: error.response.data.message, username: req.username});
    } else if (error.response && error.response.status === 409) {
      res.status(409).render('error' ,{error_code: '409', message: error.response.data.message, username: req.username});
    } else {
      res.status(500).render('error' ,{error_code: '500', message: error.message, username: req.username});
    }
  }
})

// End of Admin

// Error page
app.get('/error', (req, res) => {
  res.render('error' ,{error_code: '500', message: 'Internal Server Error', username: req.username});
})

app.use((req, res)=> {
  res.render('404', {username: req.username});
})
// End of Error

app.listen(process.env.PORT, ()=> {
  console.log('Client server is now listening on port', process.env.PORT);
})