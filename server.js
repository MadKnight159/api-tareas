
require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = 3000;

const ARCHIVO_TAREAS = path.join(__dirname, 'tareas.json');
const ARCHIVO_USUARIOS = path.join(__dirname, 'usuarios.json');
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error('Configura JWT_SECRET con una clave segura en .env');
}

// Procesar solicitudes JSON
app.use(bodyParser.json());

// Evitar escrituras simultáneas en los archivos JSON
const colas = new Map();

function ejecutarEnCola(archivo, operacion) {
    const anterior = colas.get(archivo) || Promise.resolve();
    const actual = anterior.catch(() => {}).then(operacion);

    colas.set(archivo, actual);

    actual.finally(() => {
        if (colas.get(archivo) === actual) {
            colas.delete(archivo);
        }
    }).catch(() => {});

    return actual;
}

// Leer un archivo JSON
async function leerJSON(archivo) {
    try {
        const contenido = await fs.readFile(archivo, 'utf8');
        const datos = JSON.parse(contenido);

        if (!Array.isArray(datos)) {
            throw new Error('El archivo debe contener un arreglo JSON');
        }

        return datos;
    } catch (error) {
        if (error.code === 'ENOENT') {
            return [];
        }

        throw error;
    }
}

// Guardar JSON usando fs.promises
async function guardarJSON(archivo, datos) {
    const temporal = archivo + '.tmp';

    await fs.writeFile(
        temporal,
        JSON.stringify(datos, null, 2),
        'utf8'
    );

    await fs.rename(temporal, archivo);
}

// Consultar tareas
async function obtenerTareas() {
    return leerJSON(ARCHIVO_TAREAS);
}

// Guardar tareas
async function guardarTareas(tareas) {
    return guardarJSON(ARCHIVO_TAREAS, tareas);
}

// Consultar usuarios
async function obtenerUsuarios() {
    return leerJSON(ARCHIVO_USUARIOS);
}

// Guardar usuarios
async function guardarUsuarios(usuarios) {
    return guardarJSON(ARCHIVO_USUARIOS, usuarios);
}

// Middleware para verificar JWT
function autenticarToken(req, res, next) {
    const authorization = req.headers.authorization;

    if (!authorization) {
        return res.status(401).json({
            error: 'Acceso denegado. Token requerido'
        });
    }

    const partes = authorization.split(' ');

    if (
        partes.length !== 2 ||
        partes[0] !== 'Bearer' ||
        !partes[1]
    ) {
        return res.status(401).json({
            error: 'Formato de autorización incorrecto'
        });
    }

    try {
        const usuario = jwt.verify(partes[1], JWT_SECRET, {
            algorithms: ['HS256']
        });

        req.user = usuario;
        next();
    } catch (error) {
        return res.status(403).json({
            error: 'Token inválido o expirado'
        });
    }
}

// Ruta principal
app.get('/', (req, res) => {
    res.status(200).json({
        mensaje: 'Bienvenido a la API de tareas',
        autenticacion: 'JWT',
        rutas: [
            'POST /register',
            'POST /login',
            'GET /tareas',
            'POST /tareas',
            'PUT /tareas/:id',
            'DELETE /tareas/:id'
        ]
    });
});

// Registrar usuario
app.post('/register', async (req, res, next) => {
    try {
        const { usuario, password } = req.body || {};

        if (
            typeof usuario !== 'string' ||
            !usuario.trim() ||
            typeof password !== 'string' ||
            password.length < 8
        ) {
            return res.status(400).json({
                error: 'Usuario obligatorio y contraseña de mínimo 8 caracteres'
            });
        }

        const nombre = usuario.trim();

        const resultado = await ejecutarEnCola(
            ARCHIVO_USUARIOS,
            async () => {
                const usuarios = await obtenerUsuarios();

                if (usuarios.some(u => u.usuario === nombre)) {
                    return { duplicado: true };
                }

                const passwordHash = await bcrypt.hash(password, 10);

                const nuevoUsuario = {
                    id: usuarios.reduce(
                        (max, u) => Math.max(max, u.id), 0
                    ) + 1,
                    usuario: nombre,
                    password: passwordHash
                };

                usuarios.push(nuevoUsuario);
                await guardarUsuarios(usuarios);

                return { duplicado: false };
            }
        );

        if (resultado.duplicado) {
            return res.status(409).json({
                error: 'El usuario ya existe'
            });
        }

        console.log('Usuario registrado:', nombre);

        res.status(201).json({
            mensaje: 'Usuario registrado correctamente',
            usuario: nombre
        });
    } catch (error) {
        next(error);
    }
});

// Iniciar sesión
app.post('/login', async (req, res, next) => {
    try {
        const { usuario, password } = req.body || {};

        if (
            typeof usuario !== 'string' ||
            typeof password !== 'string'
        ) {
            return res.status(400).json({
                error: 'Usuario y contraseña obligatorios'
            });
        }

        const usuarios = await obtenerUsuarios();

        const encontrado = usuarios.find(
            u => u.usuario === usuario
        );

        if (!encontrado) {
            return res.status(401).json({
                error: 'Usuario o contraseña incorrectos'
            });
        }

        const passwordValido = await bcrypt.compare(
            password,
            encontrado.password
        );

        if (!passwordValido) {
            return res.status(401).json({
                error: 'Usuario o contraseña incorrectos'
            });
        }

        const token = jwt.sign(
            {
                id: encontrado.id,
                usuario: encontrado.usuario
            },
            JWT_SECRET,
            {
                expiresIn: '1h',
                algorithm: 'HS256'
            }
        );

        console.log('Inicio de sesión:', usuario);

        res.status(200).json({
            mensaje: 'Inicio de sesión exitoso',
            token,
            tipo: 'Bearer',
            expiraEn: '1 hora'
        });
    } catch (error) {
        next(error);
    }
});

// GET: obtener todas las tareas
app.get('/tareas', autenticarToken, async (req, res, next) => {
    try {
        const tareas = await obtenerTareas();

        res.status(200).json(tareas);
    } catch (error) {
        next(error);
    }
});

// POST: crear una tarea
app.post('/tareas', autenticarToken, async (req, res, next) => {
    try {
        const { titulo, descripcion } = req.body || {};

        if (
            typeof titulo !== 'string' ||
            typeof descripcion !== 'string' ||
            !titulo.trim() ||
            !descripcion.trim()
        ) {
            return res.status(400).json({
                error: 'El título y la descripción son obligatorios'
            });
        }

        const nuevaTarea = await ejecutarEnCola(
            ARCHIVO_TAREAS,
            async () => {
                const tareas = await obtenerTareas();

                const tarea = {
                    id: tareas.reduce(
                        (max, t) => Math.max(max, t.id), 0
                    ) + 1,
                    titulo: titulo.trim(),
                    descripcion: descripcion.trim()
                };

                tareas.push(tarea);
                await guardarTareas(tareas);

                return tarea;
            }
        );

        console.log('Tarea creada:', nuevaTarea.id);

        res.status(201).json({
            mensaje: 'Tarea creada correctamente',
            tarea: nuevaTarea
        });
    } catch (error) {
        next(error);
    }
});

// PUT: actualizar una tarea
app.put('/tareas/:id', autenticarToken, async (req, res, next) => {
    try {
        const id = Number(req.params.id);
        const { titulo, descripcion } = req.body || {};

        if (!Number.isSafeInteger(id) || id <= 0) {
            return res.status(400).json({
                error: 'ID inválido'
            });
        }

        if (
            typeof titulo !== 'string' ||
            typeof descripcion !== 'string' ||
            !titulo.trim() ||
            !descripcion.trim()
        ) {
            return res.status(400).json({
                error: 'El título y la descripción son obligatorios'
            });
        }

        const tarea = await ejecutarEnCola(
            ARCHIVO_TAREAS,
            async () => {
                const tareas = await obtenerTareas();
                const encontrada = tareas.find(t => t.id === id);

                if (!encontrada) {
                    return null;
                }

                encontrada.titulo = titulo.trim();
                encontrada.descripcion = descripcion.trim();

                await guardarTareas(tareas);

                return encontrada;
            }
        );

        if (!tarea) {
            return res.status(404).json({
                error: 'Tarea no encontrada'
            });
        }

        console.log('Tarea actualizada:', id);

        res.status(200).json({
            mensaje: 'Tarea actualizada correctamente',
            tarea
        });
    } catch (error) {
        next(error);
    }
});

// DELETE: eliminar una tarea
app.delete('/tareas/:id', autenticarToken, async (req, res, next) => {
    try {
        const id = Number(req.params.id);

        if (!Number.isSafeInteger(id) || id <= 0) {
            return res.status(400).json({
                error: 'ID inválido'
            });
        }

        const tareaEliminada = await ejecutarEnCola(
            ARCHIVO_TAREAS,
            async () => {
                const tareas = await obtenerTareas();
                const indice = tareas.findIndex(t => t.id === id);

                if (indice === -1) {
                    return null;
                }

                const eliminada = tareas.splice(indice, 1)[0];

                await guardarTareas(tareas);

                return eliminada;
            }
        );

        if (!tareaEliminada) {
            return res.status(404).json({
                error: 'Tarea no encontrada'
            });
        }

        console.log('Tarea eliminada:', id);

        res.status(200).json({
            mensaje: 'Tarea eliminada correctamente',
            tarea: tareaEliminada
        });
    } catch (error) {
        next(error);
    }
});

// Rutas inexistentes
app.use((req, res) => {
    res.status(404).json({
        error: 'Ruta no encontrada'
    });
});

// Middleware general de errores
app.use((err, req, res, next) => {
    console.error('Error detectado:', err.stack);

    if (err.status === 400 && err instanceof SyntaxError) {
        return res.status(400).json({
            error: 'Formato JSON inválido'
        });
    }

    if (err.status === 413) {
        return res.status(413).json({
            error: 'Solicitud demasiado grande'
        });
    }

    res.status(500).json({
        error: 'Error interno del servidor'
    });
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
    console.log('Autenticación JWT habilitada');
});
