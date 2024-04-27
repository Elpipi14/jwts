import { Router } from "express";
import ChatManager from "../daos/mongoDb/DB/chat.manager.js";
import ProductsManager from "../daos/mongoDb/DB/productsManager.js";
import UserManager from "../daos/mongoDb/DB/userManager.js";
import { validateLogin } from "../middleware/validateLogin.js";
import passport from "passport";

// import { ProductManager } from "../daos/fileSystem/productManager.js";
// import { login } from "../controllers/users.controllers.js";
// const productManager = new ProductManager();

const routerViews = Router();
const productsDB = new ProductsManager();
const chatManager = new ChatManager();
const userManger = new UserManager();

routerViews.get('/', async (req, res) => {
    try {
        const productList = await productsDB.getAll()
        const leanProducts = productList.payload.products.map(product => product.toObject({ getters: true }))
        res.render('partials/index', { products: leanProducts, session: req.session });
    } catch (error) {
        console.error('Error getting products:', error.message);
        res.status(500).send('Internal Server Error');
    }
});

routerViews.get('/products', async (req, res) => {
    try {
        const page = req.query.page || 1;
        const productList = await productsDB.getAll(page);
        // Convierte los productos en objetos lean para evitar problemas de referencia y mejora el rendimiento
        const leanProducts = productList.payload.products.map(product => product.toObject({ getters: true }));
        // Obtiene la información de paginación de la lista de productos
        const pageInfo = productList.payload.info;
        // Renderiza la plantilla 'products' pasando la lista de productos, información de paginación y demás datos necesarios
        res.render('partials/products', { products: leanProducts, pageInfo });
    } catch (error) {
        console.error('Error al obtener productos:', error.message);
        res.status(500).send('Error interno del servidor');
    }
});

routerViews.get('/view/:id', async (req, res) => {
    try {
        // busca por params el id del producto y muestra en el render de view
        const productId = req.params.id;
        const product = await productsDB.getById(productId);
        res.render('partials/view', { product: product });
    } catch (error) {
        console.error('Error getting user profile:', error);
        res.status(500).send('Internal Server Error');
    }
});

///-------chat´s---------///

routerViews.get('/contact', async (req, res) => {
    try {
        // Obtener todos los chats desde el gestor de chats
        const chats = await chatManager.getAllChats();
        // Renderizar la plantilla Handlebars con los chats obtenidos
        res.render('partials/contact', { messages: chats });
    } catch (error) {
        console.error('Error getting chats:', error);
        res.status(500).send('Internal Server Error');
    }
});

routerViews.post('/contact/send', async (req, res) => {
    try {
        const { email, message } = req.body;
        await chatManager.createChat(email, message);
        res.redirect('/contact');
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).send('Internal Server Error');
    };
});

///-----------Login´s------------//

//Renderiza Login
routerViews.get('/login', async (req, res) => {
    res.render('partials/login');
});

routerViews.post("/login", passport.authenticate("login-jwt", { session: false }), async (req, res) =>{
    try {
        const { email, password } = req.body;
        const user = await userManger.login(email, password);
        // Verificar si el usuario está autenticado correctamente
        if (!req.isAuthenticated()) {
            return res.status(400).send("Credenciales inválidas");
        }
        if (user) {

            // Resto del código para establecer la sesión y el mensaje de bienvenida
            if (!req.session.email) {
                req.session = req.session || {};
                req.session.email = email;
                req.session.firstName = user.first_name;
                // Almacena toda la información del usuario en la sesión
                req.session.user = user;
            }
            req.session.welcomeMessage = `Bienvenido, ${user.first_name} ${user.last_name}!`;
            console.log(`Welcome message in session: ${req.session.welcomeMessage}`);
            // Aquí ya no hay error de credenciales, por lo que no debe estar dentro de este bloque
            res.redirect("/");
        } else {
            console.log("invalid credentials. Redirigiendo a /register");
            res.redirect("/login-error"); // Redirige a la página de error de registro
        }
    } catch (error) {
        console.error("Login process error", error);
        res.status(500).json({ error: "Login process error" });
    }
});

routerViews.get('/register-gitHub', passport.authenticate("github", { scope: ["user:email"] }));

routerViews.get('/gitHub', passport.authenticate('github', {failureRedirect:"/login"}), async (req, res) => {
        //La estrategia de GitHub nos retornará el usurio, entonces lo agregamos a nuestro objeto de session: 
        req.session.user = req.user;
        req.session.login = true;
        res.redirect("/profile");
    });

// ------------------------------------------------- 

//renderizar la vista register

routerViews.get('/register', async (req, res) => {
    res.render('partials/register');
});
// Ruta para procesar el formulario de registro

routerViews.post('/register', passport.authenticate("register-jwt", { session: false }), async (req, res) => {
    try {
        if (!req.user) {
            return res.status(400).send("Credenciales inválidas");
        }

        req.session.user = {
            first_name: req.user.first_name,
            last_name: req.user.last_name,
            age: req.user.age,
            gender: req.user.gender,
            email: req.user.email
        };

        req.session.login = true;

        res.redirect("/partials/profile");
    } catch (error) {
        console.error("Error en el proceso de registro", error);
        res.status(500).json({ error: "Error en el proceso de registro" });
    }
});

// ------------------------------------------------- 

// vista profile

routerViews.get('/profile', async (req, res) => {
    try {
        // Asegúrate de que el usuario esté autenticado
        if (!req.session || !req.session.user) {
            // Si no está autenticado, redirige al login
            return res.redirect('/login');
        }

        // Renderiza la vista del perfil y pasa la información del usuario
        res.render('partials/profile', { session: req.session });
    } catch (error) {
        console.error('Error getting user profile:', error.message);
        res.status(500).send('Error interno del servidor');
    }
});

//LogOut User
routerViews.get('/logout', (req, res) => {
    // Destruye la sesión del usuario
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
            res.status(500).send('Internal Server Error');
        } else {
            console.log("Close Session");
            // Redirige al usuario a la página de inicio de sesión u otra página deseada
            res.redirect('/login');
        }
    });
});

// ------------------------------------------------- 

//error vista
routerViews.get('/register-error', async (req, res) => {
    res.render('partials/register-error');
});
routerViews.get('/login-error', async (req, res) => {
    res.render('partials/login-error');
});


export default routerViews;