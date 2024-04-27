// Passport con estrategia de autenticación y autorización.
import passport from "passport";
import generationToken from "../utils/jsonWebToken.js"
import jwt from "passport-jwt";
import { UserModel } from "../daos/mongoDb/schema/user.model.js";
import { createHash, isValidPassword } from "../utils/bcryptHash.js";
import GitHubStrategy from "passport-github2";

const JWT_SECRET = "coderHouse"
const JWTStrategy = jwt.Strategy;
const ExtractJwt = jwt.ExtractJwt;

const initializePassport = () => {

    // Estrategia de registro de Usuario
       // Estrategia de registro de Usuario
       passport.use("register-jwt", new JWTStrategy({
        jwtFromRequest: ExtractJwt.fromExtractors([cookieExtractor]),
        secretOrKey: JWT_SECRET,
    }, async (jwt_payload, done) => {
        const { first_name, last_name, age, gender, email } = jwt_payload;
        try {
            console.log('Entrando en la estrategia register');
            const user = await UserModel.findOne({ email });
            if (user) {
                console.log('User already exists');
                return done(null, false, { message: "User already exists" });
            };

              // Crear un carrito para el nuevo usuario
              const cart = await cartManager.createCart({ products: [] });

            const newUser = {
                first_name,
                last_name,
                age,
                gender,
                email,
                password: createHash(password),
                cartId: cart._id, // Asignar el ID del carrito al usuario
            };

            const result = await UserModel.create(newUser);
            const token = generationToken(newUser); // Genera un token JWT para el nuevo usuario
            return done(null, { user: result, token }, { message: "Successfully registered user" });
        } catch (error) {
            return done(error);
        }

    }));

    passport.use("login-jwt", new JWTStrategy({
        jwtFromRequest: ExtractJwt.fromExtractors([cookieExtractor]),
        secretOrKey: "coderHouse",
    }, async (jwt_payload, done) => {
        try {
            // Aquí debes verificar si el usuario existe en tu base de datos
            const user = await UserModel.findOne({ email: jwt_payload.email });
    
            // Si el usuario no existe, retornar un mensaje de error
            if (!user) {
                return done(null, false, { message: "Usuario no encontrado" });
            }
    
            // Si el usuario existe, retornar el usuario
            return done(null, user);
    
        } catch (error) {
            return done(error);
        }
    }));

    passport.use("github", new GitHubStrategy({
        clientID: "Iv1.b1b1bb9978f789db",
        clientSecret: "258791470c6646f0eaa07554df5770541a57ac68",
        callbackURL: "http://localhost:8080/github",
        scope: ['user', 'users:email']
    }, async  (accessToken, refreshToken, profile, done) => {
        console.log(profile);
        const email = profile.emails && profile.emails.length > 0 ? profile.emails[0].value : null;
        const user = await UserModel.findOne({ email });
        if (user) return done(null, user);
        const newUser = await UserModel.create({
            first_name: profile._json.name,
            email,
            password: " ",
            image: profile._json.avatar_url,
            isGithub: true,
        });
        return done(null, newUser);
    }));

};

const cookieExtractor = (req) => {
    let token = null;
    if(req && req.cookies) {
        token = req.cookies["coderHouseToken"];
    }
    return token;
};

export default initializePassport;

