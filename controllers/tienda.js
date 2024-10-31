const Producto = require('../models/producto');
const Pedido = require('../models/pedido');

exports.getProductos = (req, res) => {
    Producto.find()
        .then(productos => {
            res.render('tienda/lista-productos', {
                prods: productos,
                titulo: "Productos de la tienda",
                path: "/productos",
                autenticado: req.session.autenticado
            });

        })
        .catch(err => console.log(err));
};

exports.getProducto = (req, res) => {
    const idProducto = req.params.idProducto;
    Producto.findById(idProducto)
        .then(producto => {
            if (!producto) {
                res.redirect('/');
            }
            res.render('tienda/detalle-producto', {
                producto: producto,
                titulo: producto.nombre,
                path: '/productos',
                autenticado: req.session.autenticado
            });
        })
        .catch(err => console.log(err));
}

exports.getIndex = (req, res) => {
    Producto.find()
        .then(productos => {
            res.render('tienda/index', {
                prods: productos,
                titulo: "Pagina principal de la Tienda",
                path: "/",
                autenticado: req.session.autenticado
            });
        })
        .catch(err => console.log(err));
}

exports.getCarrito = (req, res, next) => {
    req.usuario
        .populate('carrito.items.idProducto')
        .then(usuario => {
            const productos = usuario.carrito.items;
            res.render('tienda/carrito', {
                path: '/carrito',
                titulo: 'Mi Carrito',
                productos: productos,
                autenticado: req.session.autenticado
            });
        })
        .catch(err => console.log(err));
};

exports.postCarrito = (req, res) => {
    const idProducto = req.body.idProducto;

    Producto.findById(idProducto)
        .then(producto => {
            return req.usuario.agregarAlCarrito(producto);
        })
        .then(result => {
            console.log(result);
            res.redirect('/carrito');
        })
        .catch(err => console.log(err));
}

exports.postEliminarProductoCarrito = (req, res, next) => {
    const idProducto = req.body.idProducto;
    req.usuario.deleteItemDelCarrito(idProducto)
        .then(result => {
            res.redirect('/carrito');
        })
        .catch(err => console.log(err));

};

exports.getPedidos = (req, res, next) => {
    Pedido.find({'usuario.idUsuario': req.usuario._id})
        .then(pedidos => {
            res.render('tienda/pedidos', {
                path: '/pedidos',
                titulo: 'Mis Pedidos',
                pedidos: pedidos,
                autenticado: req.session.autenticado
            });
        })
        .catch(err => console.log(err));


};


exports.postPedido = (req, res, next) => {
    req.usuario
        .populate('carrito.items.idProducto')
        .then(usuario => {
            const productos = usuario.carrito.items.map(i => {
              return { cantidad: i.cantidad, producto: { ...i.idProducto._doc } };
            });
            const pedido = new Pedido({
              usuario: {
                nombre: req.usuario.nombre,
                idUsuario: req.usuario
              },
              productos: productos
            });
            return pedido.save();
          })
          .then(result => {
            return req.usuario.limpiarCarrito();
          })
          .then(() => {
            res.redirect('/pedidos');
          })
          .catch(err => console.log(err));
}; 
