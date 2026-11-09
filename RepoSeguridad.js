/**
 * PROYECTO BASE PARA TALLER DE SEGURIDAD Y EXCEPCIONES
 * Estado: VULNERABLE (Para refactorizar por los aprendices)
 */
import express from 'express';
import bcrypt from 'bcrypt';

function hashearPassword(password) {
    const saltRounds = 10;
    return bcrypt.hashSync(password, saltRounds);
}


const app = express();

app.use(express.json());

// Simulación de base de datos vulnerable
const db = {
    users: [
        { id: 1, username: 'admin', role: 'administrator', passwordHash: 'hashed_secret_999' },
        { id: 2, username: 'cristian.instructor', role: 'teacher', passwordHash: 'hashed_sena_123' }
    ]
};

// ==========================================
// RUTA 1: Consulta de usuario (Vulnerable a Inyección y Fuga de Errores)
// ==========================================
app.get('/api/users/:id', (req, res, next) => {
    try {
        // VULNERABILIDAD 1: No hay validación de tipos ni saneamiento del parámetro (OWASP A03: Injection)

        // Correccion: Validación de que el ID sea un número entero positivo
        if (!/^\d+$/.test(req.params.id)) {
            return res.status(400).json({
                error: "Invalido user id, debe ser un número entero positivo",
                received: req.params.id
            });
        }

        const userId = req.params.id;

        // Simulación de fallo en base de datos si mandan un caracter no esperado
        if (userId === 'crash') {
            throw new Error("SyntaxError: Unexpected token in SQL query near 'CRASH' at line 1 of MySQL connection pool socket.");
        }

        const user = db.users.find(u => u.id == userId);

        if (!user) {
            // VULNERABILIDAD 2: Fuga de información interna de rutas y archivos del servidor
            return res.status(404).json({
                error: "usuario no encontrado"
            });
        }

        const { passwordHash, ...userWithoutPassword } = user; // Excluyendo el campo sensible de la respuesta
        // Correccion: Se excluye el campo passwordHash de la respuesta para evitar exposición de datos sensibles
        // VULNERABILIDAD 3: Exposición de campos sensibles (passwordHash) en la respuesta
        return res.json({
            success: true,
            data: userWithoutPassword
        });
    } catch (error) {
        console.error('Error en GET /api/users/:id:', error.message);
        return next(error);
    }
});



// ==========================================
// RUTA 2: Registro de datos (Vulnerable a falta de validación y control de excepciones)
// ==========================================
app.post('/api/register', (req, res, next) => {
    try {
        const { username, role } = req.body;

        // VULNERABILIDAD 4: Ausencia total de validación de entradas (OWASP A04: Insecure Design / Injection)
        // Si envían un objeto vacío o malformado, la aplicación explota y devuelve el stack trace completo al cliente.

        // Correccion: Validación de campos obligatorios
        if (!username || !role) {
            return res.status(400).json({
                error: "Faltan campos obligatorios: username y role son requeridos",
                received: req.body
            });
        }

        // validacion de tipo de datos
        if (typeof username !== 'string' || typeof role !== 'string') {
            return res.status(400).json({
                error: "Los campos deben ser de tipo string",
                received: req.body
            });
        }

        const nameRegex = /^[a-zA-ZáéíóúÁÉÍÓÚñÑ\s]{2,100}$/;

        if (!nameRegex.test(username)) {
            return res.status(400).json({
                error: "El campo username contiene caracteres inválidos o no cumple con la longitud requerida (2-100)",
                received: username
            });
        }

        const roleRegex = /^(administrator|teacher)$/;

        if (!roleRegex.test(role)) {
            return res.status(400).json({
                error: "El campo role debe ser 'administrator' o 'teacher'",
                received: role
            });
        }

        const existingUser = db.users.find(u => u.username === username);
        if (existingUser) {
            return res.status(409).json({
                error: "El usuario ya existe",
                received: req.body
            });
        }

        const hashedPassword = hashearPassword(req.body.password);

        const newUser = {
            id: db.users.length + 1,
            username,
            role,
            passwordHash: hashedPassword
        };

        db.users.push(newUser);

        return res.status(201).json({
            message: "Usuario registrado con éxito en el servidor local",
            assignedId: newUser.id
        });
    } catch (error) {
        console.error('Error en POST /api/register:', error.message);
        return next(error);
    }
});
// Manejador de errores global por defecto (Sin filtros de seguridad ni logs seguros)
app.use((err, req, res, next) => {
    // Fuga crítica de errores internos al cliente
    res.status(500).json({
        message: "Internal Server Error unhandled exception",
        // Solucion: No exponer detalles internos de errores si el entorno es de producción.
        //details: err.message,
        //stack: err.stack // ¡Esto expone la arquitectura completa al atacante!
    });
});

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Servidor vulnerable corriendo en http://localhost:${PORT}`);
});