

<img width="1875" height="897" alt="Screenshot 2026-01-16 200517" src="https://github.com/user-attachments/assets/a85db055-60a7-48e4-9021-f1364d68bc13" />

# 🐉 Kali GPT - Asistente de Pruebas de Penetración Potenciado por IA

**Kali GPT** es un potente asistente de IA basado en terminal diseñado para pentesters y profesionales de la seguridad. Disponible en dos versiones: **Básica** para tareas simples y **Avanzada** para operaciones profesionales de red team con capacidades de ejecución de comandos.

---

## 🚀 NUEVO: Versión 3.0 - Pentester de IA Autónomo

**🔥 ACTUALIZACIÓN MAYOR: ¡La primera herramienta de pruebas de penetración con IA verdaderamente autónoma del mundo!**

### Novedades en v3.0

| Característica | Descripción |
|---------|-------------|
| 🤖 **Agente ReAct Autónomo** | IA que piensa y actúa como un pentester humano - Observar → Pensar → Actuar → Aprender |
| 🧠 **LLM Local GRATUITA (Ollama)** | ¡Sin costos de API! Privada, capaz de funcionar sin conexión, se ejecuta en tu máquina |
| 📚 **Marco MITRE ATT&CK** | Más de 50 técnicas mapeadas, sigue una metodología establecida |
| ⛓️ **Encadenamiento Inteligente de Herramientas** | Auto-selecciona la siguiente herramienta según los hallazgos (HTTP→whatweb→nikto→nuclei) |
| 💾 **Memoria Persistente** | Base de datos SQLite que recuerda intervenciones pasadas y aprende patrones |
| 🔄 **Soporte Multi-LLM** | Cambia entre Ollama (gratuito) y OpenAI (nube) en cualquier momento |

---

### 🤖 Agente Autónomo - Cómo Funciona

El agente sigue el patrón **ReAct (Razonamiento + Actuación)**:

```
┌─────────────────────────────────────────────────────────────┐
│                    AUTONOMOUS AGENT LOOP                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────┐  │
│   │ OBSERVE  │───▶│  THINK  │───▶│   ACT   │───▶│LEARN │  │
│   │          │    │          │    │          │    │      │  │
│   │ Gather   │    │ Analyze  │    │ Execute  │    │Update│  │
│   │ current  │    │ & decide │    │ tools    │    │memory│  │
│   │ state    │    │ next step│    │          │    │      │  │
│   └──────────┘    └──────────┘    └──────────┘    └──────┘  │
│        ▲                                              │     │
│        └──────────────────────────────────────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Fases de Pentesting (Metodología PTES):**
1. **Reconocimiento** → nmap, whois, theHarvester, amass
2. **Escaneo** → nmap, masscan, rustscan
3. **Enumeración** → gobuster, nikto, enum4linux, smbmap
4. **Análisis de Vulnerabilidades** → nuclei, nikto, searchsploit
5. **Explotación** → metasploit, sqlmap, hydra
6. **Post-Explotación** → linpeas, winpeas, bloodhound
7. **Informes** → Informes generados automáticamente

---

### 🧠 IA Local GRATUITA con Ollama

**¡Adiós a los costos de API!** Ejecuta la IA completamente de forma local:

```bash
# Instalar Ollama (una sola vez)
curl -fsSL https://ollama.com/install.sh | sh

# Descargar modelo (una sola vez, ~4GB)
ollama pull llama3.2

# Iniciar servidor Ollama
ollama serve
```

**Modelos Soportados:**
| Modelo | Tamaño | Mejor Para |
|-------|------|----------|
| `llama3.2` | 4GB | Uso general (recomendado) |
| `llama3.2:70b` | 40GB | Mejor calidad |
| `codellama` | 7GB | Generación de código/comandos |
| `mistral` | 4GB | Buen razonamiento |
| `phi3` | 2GB | Rápido, ligero |

**Cambia entre proveedores en cualquier momento:**
```python
# En código
ai_service.switch_provider("ollama")  # Gratuito, local
ai_service.switch_provider("openai")  # Nube, de pago
```

---

### 📚 Integración con MITRE ATT&CK

Todas las acciones están mapeadas al marco MITRE ATT&CK:

```
TACTIC                    TECHNIQUES                      TOOLS
─────────────────────────────────────────────────────────────────
Reconnaissance     T1595 Active Scanning          nmap, masscan
                   T1592 Gather Host Info         whatweb, wappalyzer
                   T1589 Gather Identity Info     theHarvester
                   
Initial Access     T1190 Exploit Public App       sqlmap, nuclei
                   T1133 External Services        hydra, medusa
                   
Discovery          T1046 Network Service Scan     nmap -sV
                   T1087 Account Discovery        enum4linux
                   T1082 System Info Discovery    linpeas
                   
Credential Access  T1110 Brute Force              hydra, john
                   T1003 Credential Dumping       mimikatz
```

---

### ⛓️ Encadenamiento Inteligente de Herramientas

Selecciona automáticamente herramientas según lo descubierto:

```
Discovery                    Auto-Chain
─────────────────────────────────────────────────────────────────
Port 80/443 open      →     whatweb → nikto → gobuster → nuclei
Port 22 open          →     ssh-audit → hydra (if weak)
Port 445 open (SMB)   →     enum4linux → smbmap → crackmapexec
WordPress detected    →     wpscan → nuclei wordpress templates
Login page found      →     hydra → sqlmap (if parameters)
```

**Ejemplo de Cadena:**
```
[+] nmap found port 80 open
    └─→ whatweb identifies WordPress 5.8
        └─→ wpscan enumerates users/plugins
            └─→ nuclei scans for CVEs
                └─→ searchsploit finds exploits
```

---

### 💾 Sistema de Memoria Persistente

Aprende de cada intervención:

```
┌─────────────────────────────────────────────────────────────┐
│                    MEMORY DATABASE                          │
├─────────────────────────────────────────────────────────────┤
│  📊 Engagements        │ Past targets, phases reached       │
│  🔓 Vulnerabilities    │ CVEs found, exploitation success   │
│  🎯 Action Patterns    │ What worked on similar targets     │
│  📈 Success Rates      │ Tool effectiveness per target type │
└─────────────────────────────────────────────────────────────┘
```

**Características:**
- Recuerda técnicas exitosas por huella del objetivo
- Sugiere acciones basadas en intervenciones similares
- Rastrea patrones de descubrimiento de vulnerabilidades
- Informa sobre la eficacia de las herramientas

---

### 🚀 Inicio Rápido v3.0

**Opción 1: Con Ollama (GRATIS - Recomendado)**
```bash
# 1. Instalar Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2
ollama serve

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Ejecutar modo autónomo
python kali-gpt-autonomous.py
```

**Opción 2: Con OpenAI (Nube)**
```bash
# 1. Establecer clave API
export OPENAI_API_KEY=your-key-here

# 2. Ejecutar
python kali-gpt-autonomous.py --provider openai
```

**Opciones de Línea de Comandos:**
```bash
python kali-gpt-autonomous.py --help

Options:
  -t, --target TARGET      Target for immediate scan
  -p, --provider PROVIDER  AI provider: ollama, openai, auto
  -m, --model MODEL        Model name (e.g., llama3.2, gpt-4o)
```

---

### 🎮 Ejemplos de Uso

**1. Iniciar Prueba Autónoma:**
```bash
python kali-gpt-autonomous.py

# Menu:
# 1. 🎯 Autonomous Test - AI decides everything
# 2. 👣 Step-by-Step - You confirm each action
# 3. 🔧 Quick Scan - Single nmap scan
# 4. ❓ Ask AI - Security questions
```

**2. Objetivo IP Específica:**
```bash
python kali-gpt-autonomous.py --target 192.168.1.100
```

**3. Usar Modelo Específico:**
```bash
python kali-gpt-autonomous.py --provider ollama --model codellama
```

**4. Cambiar Proveedor a Mitad de Sesión:**
```
> Menu option 6 (Provider)
> Current: ollama (llama3.2)
> Switch to: openai
> [+] Switched to OpenAI (gpt-4o)
```

---

### 📊 Estado y Hoja de Ruta

| Fase | Estado | Descripción |
|-------|--------|-------------|
| Fase 1 | ✅ Completado | Agente Autónomo + LLM Local |
| Fase 2 | ✅ Completado | MITRE ATT&CK + Encadenamiento de Herramientas |
| Fase 3 | ✅ Completado | Generación de Informes |
| Fase 4 | 🔄 En Progreso | Visualización de Árbol de Ataque |
| Fase 5 | ⏳ Planificado | LLM de Seguridad Ajustada Fino |
| Fase 6 | ⏳ Planificado | Colaboración Multi-Agente |

---

## 📦 Tres Versiones Disponibles

### 🔷 Kali GPT (Básica)
Asistente de IA simple y ligero para:
- Preguntas rápidas sobre herramientas de seguridad
- Generación básica de payloads
- Explicaciones de herramientas
- Aprendizaje de conceptos básicos de pentesting

### 🔶 Kali GPT Avanzada
Asistente de grado profesional con:
- ⚡ **Ejecución de Comandos**: Ejecutar y analizar herramientas Kali directamente
- 🎯 **7 Perfiles de Seguridad**: Modos especializados (Reconocimiento, Explotación, Web, Inalámbrico, etc.)
- 🧠 **IA Consciente del Contexto**: Mantiene el historial de conversaciones
- 🔧 **Automatización de Flujos de Trabajo**: Flujos de pentesting multietapa
- 📋 **Generación Avanzada de Payloads**: Con técnicas de evasión
- 🔍 **Análisis de Salida**: Interpretación de resultados potenciada por IA
- 🛡️ **Controles de Seguridad**: Protección contra comandos peligrosos

➡️ **[Leer Documentación Avanzada](README_ADVANCED.md)** para todas las características

### ⭐ Kali GPT Enhanced v2.0 (NUEVO - Recomendado)
Plataforma de pruebas de penetración de nivel empresarial con todas las características avanzadas MÁS:
- 🎯 **Integración con Metasploit Framework**: Explotación automatizada y generación de payloads
- 📊 **Perfiles de Herramientas Personalizados**: Crea perfiles especializados para tu flujo de trabajo
- 📈 **Generación de Informes**: Informes profesionales en HTML, Markdown y JSON
- 🎯 **Gestión Multi-Objetivo**: Rastrea múltiples objetivos con hallazgos y notas
- 🔌 **Sistema de Plugins**: Arquitectura extensible para funcionalidad personalizada
- 👥 **Colaboración en Equipo**: Comparte sesiones y coordina con miembros del equipo
- 🔍 **Escaneo Automatizado de Vulnerabilidades**: Nmap, Nikto y escáneres personalizados integrados
- 🌐 **Integración con Bases de Datos de Vulnerabilidades**: Búsquedas en tiempo real de CVE, NVD y ExploitDB

➡️ **[Leer Documentación de Características](FEATURES.md)** para la lista completa

---

## 🚀 Instalación Rápida

### Configuración Automatizada (Recomendada)

```bash
# Clonar repositorio
git clone https://github.com/alishahid74/kali-gpt
cd kali-gpt

# Ejecutar script de instalación
chmod +x setup.sh
./setup.sh

# Si aún encuentras el error:
# "bad interpreter: /bin/bash^M"
# corregir terminaciones de línea de Windows y ejecutar de nuevo
sed -i 's/\r$//' setup.sh
./setup.sh


# Agregar tu clave API de OpenAI
nano .env
# Agregar: OPENAI_API_KEY=your-api-key-here

# Activar entorno
source venv/bin/activate

# Ejecutar versión Enhanced (recomendada para profesionales)
python3 kali-gpt-enhanced.py

# O ejecutar versión Avanzada

./kali-gpt-advanced.py

# O ejecutar versión Básica
./kali-gpt.py
```

### Instalación Manual

```bash
# Clonar repositorio
git clone https://github.com/alishahid74/kali-gpt
cd kali-gpt

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Crear archivo .env
echo "OPENAI_API_KEY=your-api-key-here" > .env

# Editar .env y agregar tu clave API real
nano .env

# Ejecutar la herramienta
./kali-gpt-advanced.py
```

---

## 🔑 Obtener Clave API de OpenAI

1. Ve a [OpenAI Platform](https://platform.openai.com/api-keys)
2. Regístrate o inicia sesión
3. Haz clic en "Create new secret key"
4. Copia la clave y agrégala al archivo `.env`

---

## 🎮 Guía de Inicio Rápido

### Versión Básica
```bash
source venv/bin/activate
./kali-gpt.py
```

Interfaz simple basada en menú para:
- Hacer preguntas de ciberseguridad
- Generar payloads básicos
- Obtener explicaciones de herramientas

### Versión Avanzada
```bash
source venv/bin/activate
./kali-gpt-advanced.py
```

**Opciones del Menú Principal:**
1. 💬 Preguntas Asistidas por IA - Preguntar cualquier cosa sobre pentesting
2. ⚡ Generación Rápida de Comandos - Generar comandos al instante
3. 🎯 Ejecutar Comandos - Ejecutar herramientas con análisis de IA
4. 🔧 Constructor de Flujos de Trabajo - Automatizar procesos multietapa
5. 🛡️ Perfiles de Seguridad - Cambiar entre modos especializados
6. 📋 Generador de Payloads - Creación avanzada de payloads
7. 🔍 Análisis de Salida - Analizar resultados de herramientas
8. 📚 Historial de Conversaciones - Revisar interacciones pasadas
9. ⚙️ Configuración - Personalizar comportamiento

---

## 🧰 Requisitos

- **SO**: Kali Linux (o cualquier distro basada en Debian)
- **Python**: 3.8 o superior
- **Clave API**: Clave API de OpenAI (GPT-4 recomendado)
- **Herramientas**: xclip (para soporte de portapapeles)

---

## 📖 Documentación

- **[README_ADVANCED.md](README_ADVANCED.md)** - Guía completa de características avanzadas
- **[config.example.json](config.example.json)** - Opciones de configuración

---

## 🎯 Ejemplos de Uso

### Ejemplo de Reconocimiento
```
Usuario: ¿Cómo enumero subdominios para target.com?
IA: [Proporciona múltiples herramientas y comandos]

Usuario: [Selecciona comando para ejecutar]
Sistema: [Ejecuta comando con confirmación]
IA: [Analiza resultados y sugiere siguientes pasos]
```

### Ejemplo de Explotación
```
Usuario: Genera payloads de reverse shell para objetivo Linux
IA: [Crea payloads bash, python, nc + configuración de listener]

Usuario: [Copia payload, configura listener]
```

### Ejemplo de Pruebas Web
```
Usuario: Construye flujo de trabajo para pruebas de app web en https://target.com
IA: [Crea flujo de trabajo paso a paso]
  1. Enumeración de directorios con ffuf
  2. Escaneo de vulnerabilidades con nikto
  3. Pruebas de inyección SQL con sqlmap
  4. Detección de XSS
  [Cada uno con comandos específicos y análisis]
```

---

## 🛡️ Perfiles de Seguridad (Solo Avanzada)

Cambia entre modos especializados de IA:

- 🎯 **Pentesting General** - Guía general equilibrada
- 🔍 **Reconocimiento** - Enfoque en OSINT y escaneo
- ⚡ **Explotación** - Explotación de vulnerabilidades
- 🌐 **Aplicación Web** - Pruebas OWASP Top 10
- 📡 **Seguridad Inalámbrica** - Ataques WiFi
- 🔐 **Post-Explotación** - Persistencia y movimiento lateral
- 🔬 **Forensia Digital** - Evidencia y análisis

---

## ⚙️ Configuración

La versión avanzada usa: `~/.kali-gpt/config.json`

```json
{
  "model": "gpt-4o",
  "temperature": 0.7,
  "require_confirmation": true,
  "auto_copy": true,
  "save_history": true
}
```

---

## 🐛 Solución de Problemas

### Clave API No Funciona
```bash
# Verificar archivo .env
cat .env
# Debería mostrar: OPENAI_API_KEY=sk-...

# Asegúrate de que no haya espacios alrededor de =
# Correcto: OPENAI_API_KEY=sk-xxx
# Incorrecto: OPENAI_API_KEY = sk-xxx
```

### Errores de Permisos
```bash
# Hacer scripts ejecutables
chmod +x kali-gpt.py kali-gpt-advanced.py

# Para comandos del sistema que necesitan root
sudo ./kali-gpt-advanced.py
```

### Módulo No Encontrado
```bash
# Asegurarse de que el entorno virtual esté activado
source venv/bin/activate

# Reinstalar dependencias
pip install -r requirements.txt --force-reinstall
```

---

## 🔐 Seguridad y Ética

### ⚠️ Directrices Importantes

- ✅ **Solo probar sistemas autorizados**
- ✅ **Usar para pentesting legal, CTFs, investigación**
- ✅ **Respetar leyes de privacidad y protección de datos**
- ❌ **Nunca usar para acceso no autorizado**
- ❌ **Nunca usar para propósitos maliciosos**

### Privacidad de Datos
- Todos los registros se almacenan localmente en `~/.kali-gpt/`
- Las solicitudes API se envían solo a OpenAI
- Sin compartición de datos con terceros
- Protege tu clave API en `.env`

---

## 🚀 Destacados de Características Avanzadas

### Ejecución de Comandos con Seguridad
- Detección automática de comandos peligrosos
- Confirmación antes de ejecución
- Protección contra tiempo de espera
- Controles de modo seguro

### Flujos de Trabajo Inteligentes
- Automatización de pentesting multietapa
- Sugerencias conscientes del contexto
- Capacidades de encadenamiento de herramientas
- Toma de decisiones basada en resultados

### Análisis de Salida
- Interpretación de resultados potenciada por IA
- Identificación de vulnerabilidades
- Recomendaciones de siguientes pasos
- Priorización de hallazgos

---

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Por favor:
- Seguir la divulgación responsable
- Agregar controles de seguridad para nuevas características
- Actualizar documentación
- Probar exhaustivamente

---

## ⚠️ Descargo de Responsabilidad

Esta herramienta es para **pruebas de seguridad autorizadas y fines educativos únicamente**. Los usuarios deben asegurar la autorización adecuada antes de probar cualquier sistema. El autor no se hace responsable por uso indebido.

**Usa responsablemente. Hackea éticamente. Mantente en la legalidad.** 🐉

---

## 🔗 Enlaces

- **GitHub**: [https://github.com/alishahid74/kali-gpt](https://github.com/alishahid74/kali-gpt)
- **API OpenAI**: [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys)
- **Docs Avanzadas**: [README_ADVANCED.md](README_ADVANCED.md)
