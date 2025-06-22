import React, { useState, useEffect } from 'react';
import Editor from 'react-simple-code-editor'; 
import { Light as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vs2015 } from 'react-syntax-highlighter/dist/esm/styles/hljs'; // O elige otro estilo, vs2015 es oscuro
import { javascript } from 'react-syntax-highlighter/dist/esm/languages/hljs'; // Importa el lenguaje específico

import styles from '../styles/DiagramEditorPage.module.css'; // Crearemos este archivo CSS
import { useNavigate } from 'react-router-dom'; // Importa useNavigate

SyntaxHighlighter.registerLanguage('javascript', javascript); 

function DiagramEditorPage() {
  const [code, setCode] = useState(`// Escribe tu código de diagrama aquí
// Por ejemplo:
// graph TD;
//    A-->B;
//    A-->C;
//    B-->D;
//    C-->D;
`);
  const [diagramImageSrc, setDiagramImageSrc] = useState(null); // Para la URL de la imagen del diagrama
  const [diagramType, setDiagramType] = useState('Mermaid'); // Valor por defecto. Puedes expandir esto.
  const navigate = useNavigate(); // Inicializa useNavigate

  const handleLogoutClick = () => {
    if (onLogout) {
      onLogout(); // Llama a la función de logout pasada desde App.jsx
    }
    navigate('/login'); // Redirige de vuelta a la página de login
  };

  // Simulamos la llamada al backend para generar el diagrama
  const generateDiagram = () => {
    if (!code.trim()) {
      alert('Por favor, ingresa código para generar el diagrama.');
      return;
    }
    console.log('Enviando código al backend para generar diagrama:', code); 
    console.log('Tipo de diagrama seleccionado:', diagramType);

    // --- Simulación de llamada al Backend ---
    // En una aplicación real, aquí harías una petición fetch/axios al backend
    // fetch('/api/generate-diagram', {
    //   method: 'POST',
    //   headers: {
    //     'Content-Type': 'application/json',
    //     'Authorization': `Bearer ${yourAuthToken}` // Se necesita un token para rutas protegidas 
    //   },
    //   body: JSON.stringify({ code, type: diagramType })
    // })
    // .then(response => response.json())
    // .then(data => {
    //   if (data.diagramUrl) { // Asumimos que el backend retorna una URL o base64 de la imagen 
    //     setDiagramImageSrc(data.diagramUrl); // O `data.diagramBase64` si es base64
    //   } else {
    //     alert('Error al generar el diagrama: ' + data.message); 
    //     setDiagramImageSrc(null);
    //   }
    // })
    // .catch(error => {
    //   console.error('Error al comunicarse con el backend:', error);
    //   alert('Ocurrió un error al intentar generar el diagrama.');
    // });

    // --- Simulación de respuesta del Backend (remplazar con la lógica real) ---
    // Por ahora, simplemente mostraremos un placeholder o un mensaje.
    setTimeout(() => {
      // Simula que el backend devuelve una URL de imagen SVG
      const svgPlaceholder = `data:image/svg+xml;base64,${btoa(`
        <svg width="400" height="200" xmlns="http://www.w3.org/2000/svg">
          <rect width="100%" height="100%" fill="#f0f0f0"/>
          <text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-family="Arial" font-size="20" fill="#333">
            Diagrama Generado Aquí (${diagramType})
          </text>
          <text x="50%" y="70%" dominant-baseline="middle" text-anchor="middle" font-family="Arial" font-size="14" fill="#666">
            (Código simulado: ${code.substring(0, 30)}...)
          </text>
        </svg>
      `)}`;
      setDiagramImageSrc(svgPlaceholder);
      console.log('Diagrama generado y mostrado.');
    }, 1000); // Simula un retraso de red
  };

  const handleFileUpload = (event) => {
    const file = event.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        setCode(e.target.result);
      };
      reader.readAsText(file);
    }
  };

  const handlePasteFromClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setCode(text);
      alert('Texto pegado desde el portapapeles.');
    } catch (err) {
      console.error('Error al pegar del portapapeles:', err);
      alert('No se pudo pegar el texto del portapapeles. Asegúrate de haber concedido permisos.');
    }
  };

  const handleLoadFromGitHub = () => {
    const githubUrl = prompt('Ingresa la URL del archivo de GitHub (raw):');
    if (githubUrl) {
      // Aquí se podría validar que sea una URL de archivo raw válida
      fetch(githubUrl)
        .then(response => {
          if (!response.ok) {
            throw new Error('No se pudo cargar el archivo desde GitHub. Código: ' + response.status);
          }
          return response.text();
        })
        .then(text => {
          setCode(text);
          alert('Código cargado desde GitHub exitosamente.');
        })
        .catch(error => {
          console.error('Error cargando desde GitHub:', error);
          alert('Error al cargar el código desde GitHub: ' + error.message);
        });
    }
  };

  const handleExportDiagram = (format) => {
    if (!diagramImageSrc) {
      alert('Primero genera un diagrama para poder exportarlo.');
      return;
    }
    // Lógica de exportación. Esto es más complejo y a menudo requiere una librería o backend.
    // Para PNG/SVG directo desde la imagen en pantalla:
    if (diagramImageSrc.startsWith('data:image/svg+xml') && (format === 'SVG' || format === 'PNG')) {
      const svgContent = atob(diagramImageSrc.split(',')[1]);
      if (format === 'SVG') {
        const blob = new Blob([svgContent], { type: 'image/svg+xml' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `diagrama.svg`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } else if (format === 'PNG') {
        // Convertir SVG a PNG en el cliente es complejo y requiere Canvas.
        // Por simplicidad, se puede enviar el SVG al backend para conversión.
        // Aquí solo alertamos para PNG.
        alert(`Exportar a PNG/PDF generalmente requiere el backend para una conversión robusta del SVG/imagen actual. Simulación de descarga de ${format}.`);
        // Lógica real: crear un canvas, dibujar el SVG, luego exportar como PNG
        // const img = new Image();
        // img.src = diagramImageSrc; // Si ya es SVG, se puede usar
        // img.onload = () => {
        //   const canvas = document.createElement('canvas');
        //   canvas.width = img.width;
        //   canvas.height = img.height;
        //   const ctx = canvas.getContext('2d');
        //   ctx.drawImage(img, 0, 0);
        //   const pngUrl = canvas.toDataURL('image/png');
        //   const a = document.createElement('a');
        //   a.href = pngUrl;
        //   a.download = 'diagrama.png';
        //   document.body.appendChild(a);
        //   a.click();
        //   document.body.removeChild(a);
        // };
      }
    } else {
      alert(`Exportando diagrama en formato ${format}... (Lógica de exportación a ${format} aún no implementada completamente en el frontend para todos los casos).`);
    }
  };


  return (
    <div className={styles.container}>
      <header className={styles.header}>
        <h1 className={styles.title}>Diagram as Code Editor</h1>
        {/* Añadir botón de Logout */}
        <button onClick={handleLogoutClick} className={styles.logoutButton}>Cerrar Sesión</button>
      </header>

      <div className={styles.contentWrapper}>
        <div className={styles.editorPanel}>
          <div className={styles.controls}>
            <label htmlFor="diagramType" className={styles.label}>Tipo de Diagrama:</label>
            <select
              id="diagramType"
              value={diagramType}
              onChange={(e) => setDiagramType(e.target.value)}
              className={styles.select}
            >
              <option value="Mermaid">Mermaid (ej. Graph, Flowchart)</option>
              <option value="AWS">AWS Architecture</option> 
              <option value="ER">Entity-Relationship (E-R)</option> 
              <option value="JSON">JSON Structure</option> 
              {/* Puedes añadir más opciones aquí para otros lenguajes de diagramas */}
            </select>
            <input
              type="file"
              accept=".txt"
              onChange={handleFileUpload}
              className={styles.fileInput}
              id="fileUpload"
            />
            <label htmlFor="fileUpload" className={styles.fileInputLabel}>Subir Archivo (.txt)</label> 
            <button onClick={handlePasteFromClipboard} className={styles.controlButton}>Pegar de Portapapeles</button> 
            <button onClick={handleLoadFromGitHub} className={styles.controlButton}>Cargar desde GitHub</button> 

          </div>

          <Editor
            value={code}
            onValueChange={setCode}
            padding={10} // Mantén el padding del componente Editor aquí
            className={styles.editor} // Tu clase CSS para estilos generales del editor
            style={{
              // Estilos para el contenedor principal del Editor (el div con class .editor)
              fontFamily: '"Fira code", "Fira Mono", monospace',
              fontSize: 16,
              // ¡CRÍTICO! Sobrescribe el overflow: hidden; que viene del componente
              overflow: 'auto', // Forzar scroll vertical y horizontal en el contenedor principal
            }}
            textareaClassName={styles.editorTextarea} // Asigna una clase para el textarea si necesitas más control CSS
            textareaStyle={{
              // Estilos para el textarea subyacente
              // ¡CRÍTICO! Sobrescribe el overflow: hidden; que viene del textarea
              overflow: 'auto', // Forzar scroll vertical y horizontal en el textarea
              // Asegurarse de que el color del texto del textarea sea transparente
              color: 'transparent',
              // Asegurarse de que el cursor sea visible
              caretColor: '#fff', // O el color que desees para el cursor
            }}
            highlight={(codeToHighlight) => (
              <SyntaxHighlighter
                language="javascript"
                customStyle={{
                  background: 'transparent',
                }}
              >
                {codeToHighlight}
              </SyntaxHighlighter>
            )}
          />
          <button onClick={generateDiagram} className={styles.generateButton}>Generar Diagrama</button> 
        </div>

        <div className={styles.diagramPanel}>
          <h2 className={styles.diagramTitle}>Visualización del Diagrama</h2>
          <div className={styles.diagramDisplay}>
            {diagramImageSrc ? (
              <img src={diagramImageSrc} alt="Diagrama Generado" className={styles.diagramImage} /> 
            ) : (
              <p className={styles.noDiagramMessage}>El diagrama se mostrará aquí después de generarlo.</p> 
            )}
          </div>
          <div className={styles.exportControls}>
            <button onClick={() => handleExportDiagram('PNG')} className={styles.exportButton}>Exportar PNG</button> 
            <button onClick={() => handleExportDiagram('SVG')} className={styles.exportButton}>Exportar SVG</button> 
            <button onClick={() => handleExportDiagram('PDF')} className={styles.exportButton}>Exportar PDF</button> 
          </div>
        </div>
      </div>
    </div>
  );
}

export default DiagramEditorPage;