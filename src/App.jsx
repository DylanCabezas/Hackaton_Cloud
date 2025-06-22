import React, { useState } from 'react'; // Importa useState
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import LoginPage from './pages/LoginPage';
import DiagramEditorPage from './pages/DiagramEditorPage';

function App() {
  // Estado para controlar la autenticación del usuario
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Función para manejar el login exitoso (establecer isAuthenticated en true)
  const handleLoginSuccess = () => {
    setIsAuthenticated(true);
    // En una aplicación real, aquí guardarías el token JWT en localStorage o cookies
  };

  // Función para manejar el logout (establecer isAuthenticated en false)
  const handleLogout = () => {
    setIsAuthenticated(false);
    // En una aplicación real, aquí eliminarías el token JWT
    // navigate('/login'); // Opcional: redirigir a login después de logout
  };

  return (
    <Router>
      <Routes>
        <Route
          path="/login"
          // Pasa la función handleLoginSuccess al componente LoginPage
          element={<LoginPage onLoginSuccess={handleLoginSuccess} />}
        />
        {/* Proteger la ruta del editor */}
        <Route
          path="/editor"
          element={isAuthenticated ? <DiagramEditorPage onLogout={handleLogout} /> : <Navigate to="/login" />}
        />
        {/* Redirigir la ruta raíz a login si no está autenticado */}
        <Route path="/" element={<Navigate to={isAuthenticated ? "/editor" : "/login"} />} />
      </Routes>
    </Router>
  );
}

export default App;