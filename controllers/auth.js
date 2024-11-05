const Usuario = require('../models/usuario')
const bcrypt = require('bcryptjs');
const crypto = require('crypto');


const nodemailer = require('nodemailer');
const sendgridTransport = require('nodemailer-sendgrid-transport');


// AQUI_SE_PONE_EL_API_KEY
const APIKEY = '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';

const transporter = nodemailer.createTransport(
  sendgridTransport({
    auth: {
      api_key:
        APIKEY
    }
  })
);


let esPasswordComplejo = (password) => {
  return password.length > 7;
}

exports.getIngresar = (req, res, next) => {
    let mensaje = req.flash('error');
    if (mensaje.length > 0) {
      mensaje = mensaje[0];
    } else {
      mensaje = null;
    }
    res.render('auth/ingresar', {
      path: '/ingresar',
      titulo: 'Ingresar',
      autenticado: false,
      mensajeError: mensaje
    });
  };

exports.postIngresar = (req, res, next) => {
    const email = req.body.email;
    const password = req.body.password;
    Usuario.findOne({ email: email })
    .then(usuario => {
      if (!usuario) {
        req.flash('error', 'El usuario no existe')
        return res.redirect('/ingresar');
      }
      bcrypt.compare(password, usuario.password)
        .then(hayCoincidencia => {
          if(hayCoincidencia) {
            req.session.autenticado = true;
            req.session.usuario = usuario;
            return req.session.save(err => {
              console.log(err);
              res.redirect('/')
            })
          }
          req.flash('error', 'Las credenciales son invalidas')
          res.redirect('/ingresar');
        })
        .catch(err => console.log(err));
      })
};

exports.getRegistrarse = (req, res, next) => {
  let mensaje = req.flash('error');
  if (mensaje.length > 0) {
    mensaje = mensaje[0];
  } else {
    mensaje = null;
  }
  res.render('auth/registrarse', {
    path: '/registrarse',
    titulo: 'Registrarse',
    autenticado: false,
    mensajeError: mensaje
  });
};

exports.postRegistrarse = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const passwordConfirmado = req.body.passwordConfirmado;
  
  if (password !== passwordConfirmado) {
    req.flash('error', 'Debe usar el mismo password')
    res.redirect('/registrarse');
  }
  if (!esPasswordComplejo(password)) {
    req.flash('error', 'El password debe tener longitud minima de 8 caracteres, letras y numeros....')
    res.redirect('/registrarse');
  }
  Usuario.findOne({ email: email })
    .then(usuarioDoc => {
      if (usuarioDoc) {
        req.flash('error', 'Dicho email ya esta en uso')
        return res.redirect('/registrarse');
      }
      return bcrypt.hash(password, 12)
        .then(passwordCifrado => {
          const usuario = new Usuario({
            email: email,
            password: passwordCifrado,
            carrito: { items: [] }
          });
          return usuario.save();
        });
    })
    .then(result => {
      console.log(result);
      res.redirect('/ingresar');
      return transporter.sendMail({
        to: email,
        from: 'santaaparicioc@gmail.com', // El email que fue verificado en SendGrid
        subject: 'Bienvenido, tu registro fue exitoso',
        html: '<h1>Se ha dado de alta satisfactoriamente!</h1>'
      })
    })
    .catch(err => {
      console.log(err);
    });
};

exports.postSalir = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};


exports.getReinicio = (req, res, next) => {
  let mensaje = req.flash('error');
  if (mensaje.length > 0) {
    mensaje = mensaje[0];
  } else {
    mensaje = null;
  }
  res.render('auth/reinicio', {
    path: '/reinicio',
    titulo: 'Reinicio Password',
    mensajeError: mensaje
  });
};



exports.postReinicio = (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
      return res.redirect('/reinicio');
    }
    const token = buffer.toString('hex');
    Usuario.findOne({ email: req.body.email })
      .then(usuario => {
        if (!usuario) {
          req.flash('error', 'No se encontro usuario con dicho email');
          return res.redirect('/reinicio');
        }
        usuario.tokenReinicio = token;
        usuario.expiracionTokenReinicio = Date.now() + 3600000; // + 1 hora
        return usuario.save();
      })
      .then(result => {
        res.redirect('/');
        transporter.sendMail({
          to: req.body.email,
          from: 'jcabelloc@itana.pe',
          subject: 'Reinicio de Password',
          html: `
            <p>Tu has solicitado un reinicio de password</p>
            <p>Click aqui <a href="http://localhost:3000/reinicio/` + token + `">link</a> para establecer una nuevo password.</p>
          `
        });
      })
      .catch(err => {
        console.log(err);
      });
  });
};




exports.getNuevoPassword = (req, res, next) => {
  const token = req.params.token;
  console.log(token)
  Usuario.findOne({ tokenReinicio: token, expiracionTokenReinicio: { $gt: Date.now() } })
    .then(usuario => {
      console.log(usuario)
      let mensaje = req.flash('error');
      if (mensaje.length > 0) {
        mensaje = mensaje[0];
      } else {
        mensaje = null;
      }
      res.render('auth/nuevo-password', {
        path: '/nuevo-password',
        titulo: 'Nuevo Password',
        mensajeError: mensaje,
        idUsuario: usuario._id.toString(),
        tokenPassword: token
      });
    })
    .catch(err => {
      console.log(err);
    });
};


exports.postNuevoPassword = (req, res, next) => {
  const nuevoPassword = req.body.password;
  const idUsuario = req.body.idUsuario;
  const tokenPassword = req.body.tokenPassword;
  let usuarioParaActualizar;

  Usuario.findOne({
    tokenReinicio: tokenPassword,
    expiracionTokenReinicio: { $gt: Date.now() },
    _id: idUsuario
  })
    .then(usuario => {
      usuarioParaActualizar = usuario;
      return bcrypt.hash(nuevoPassword, 12);
    })
    .then(hashedPassword => {
      usuarioParaActualizar.password = hashedPassword;
      usuarioParaActualizar.tokenReinicio = undefined;
      usuarioParaActualizar.expiracionTokenReinicio = undefined;
      return usuarioParaActualizar.save();
    })
    .then(result => {
      res.redirect('/ingresar');
    })
    .catch(err => {
      console.log(err);
    });
};

