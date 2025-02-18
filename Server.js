const express = require("express");
const sql = require("mssql");
const csv = require("fast-csv");
const fs = require("fs");
const path = require("path");
const bodyParser = require("body-parser");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const port = process.env.PORT;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(helmet());
app.use(express.json());
app.use(bodyParser.json());
app.use(cors());

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: "Demasiados intentos, por favor intente más tarde"
});

function escapeSqlName(name) {
    return "[" + name.replace(/\]/g, "]]") + "]";
}

function verifyToken(req, res, next) {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ error: "Acceso denegado" });
    try {
        const verified = jwt.verify(token.replace("Bearer ", ""), JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ error: "Token inválido" });
    }
}

app.post("/login", loginLimiter, async (req, res) => {
    const { DBUser, DBPassword, DBServer, DBName } = req.body;
    if (!DBUser || !DBPassword || !DBServer || !DBName) {
        return res.status(400).json({ error: "Faltan campos requeridos" });
    }

    const config = {
        user: DBUser,
        password: DBPassword,
        server: DBServer,
        database: DBName,
        options: { encrypt: false, trustServerCertificate: true }
    };

    try {
        await sql.connect(config);
        console.log("Conexión exitosa a SQL Server");
        const token = jwt.sign({ user: DBUser }, JWT_SECRET, { expiresIn: "1h" });
        res.json({ message: "Conexión exitosa", token });
    } catch (err) {
        console.error("Error de conexión:", err);
        res.status(500).json({ error: "Error de autenticación" });
    }
});

app.get("/schemas", verifyToken, async (req, res) => {
    try {
        const query = `
            SELECT DISTINCT schema_name 
            FROM information_schema.schemata 
            WHERE schema_name NOT IN ('dbo', 'guest', 'INFORMATION_SCHEMA', 'sys',
                                     'db_owner', 'db_accessadmin', 'db_securityadmin', 
                                     'db_ddladmin', 'db_backupoperator', 'db_datareader', 
                                     'db_datawriter', 'db_denydatareader', 'db_denydatawriter')
        `;
        const result = await sql.query(query);
        res.json({ schemas: result.recordset.map(row => row.schema_name) });
    } catch (err) {
        console.error("Error al obtener los esquemas:", err);
        res.status(500).json({ error: "Error al obtener los esquemas" });
    }
});

app.get("/tables/:schema", verifyToken, async (req, res) => {
    const { schema } = req.params;
    try {
        const request = new sql.Request();
        request.input("schema", sql.NVarChar, schema);
        const schemaQuery = "SELECT schema_name FROM information_schema.schemata WHERE schema_name = @schema";
        const schemaResult = await request.query(schemaQuery);

        if (schemaResult.recordset.length === 0) {
            return res.status(400).json({ error: "Esquema no válido" });
        }

        const tableQuery = `SELECT table_name FROM information_schema.tables WHERE table_schema = @schema`;
        const result = await request.query(tableQuery);
        res.json({ tables: result.recordset.map(row => row.table_name) });
    } catch (err) {
        console.error("Error al obtener las tablas:", err);
        res.status(500).json({ error: "Error interno del servidor" });
    }
});

app.get("/export/:schema/:table", verifyToken, async (req, res) => {
    const { schema, table } = req.params;
    try {
        const request = new sql.Request();
        request.input("schema", sql.NVarChar, schema);
        request.input("table", sql.NVarChar, table);

        const tableResult = await request.query(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = @schema AND table_name = @table"
        );
        if (tableResult.recordset.length === 0) {
            return res.status(400).json({ error: "Tabla no válida" });
        }

        const escapedSchema = escapeSqlName(schema);
        const escapedTable = escapeSqlName(table);
        const query = `SELECT * FROM ${escapedSchema}.${escapedTable}`;
        const result = await sql.query(query);

        if (result.recordset.length === 0) {
            return res.status(404).json({ error: "No hay datos disponibles" });
        }

        const filename = `${table}_export.csv`;
        const filePath = path.join(__dirname, filename);
        const ws = fs.createWriteStream(filePath);

        csv.write(result.recordset, { headers: true })
            .pipe(ws)
            .on("finish", () => {
                res.download(filePath, filename, (err) => {
                    if (err) console.error("Error al descargar:", err);
                    fs.unlinkSync(filePath);
                });
            });
    } catch (err) {
        console.error("Error en exportación:", err);
        res.status(500).json({ error: "Error interno del servidor" });
    }
});

app.get("/verificartoken", verifyToken, async (req, res) => {
    res.status(200).json({ message: "Token válido" });
});

app.get("/verificarsesion", verifyToken, async (req, res) => {
    try {
        await sql.query("SELECT 1 AS status");
        res.status(200).json({ message: "Sesión válida, conexión a la base de datos activa" });
    } catch (err) {
        console.error("Error en la verificación de sesión:", err);
        res.status(500).json({ error: "Sesión no válida o conexión a la base de datos fallida" });
    }
});

app.get("/", (req, res) => {
    res.json("Servidor funcionando correctamente");
});

app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
