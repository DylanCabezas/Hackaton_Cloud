import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import styles from '../styles/LoginPage.module.css';

// Recibe onLoginSuccess como prop
function LoginPage({ onLoginSuccess }) {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const navigate = useNavigate();

  const handleToggleForm = () => {
    setIsLogin(!isLogin);
    setEmail('');
    setPassword('');
    if (!isLogin) setConfirmPassword('');
  };

  const handleSubmit = (event) => {
    event.preventDefault();

    if (isLogin) {
      console.log('Intentando iniciar sesión con:', { email, password });
      // Simulación de autenticación exitosa.
      // En un proyecto real, esto sería una llamada al backend.
      const simulatedLoginSuccess = true; // Cambiar a false para simular falla
      if (simulatedLoginSuccess) {
        alert('Login simulado exitoso. Redirigiendo...');
        // Llama a la función pasada desde App.jsx para actualizar el estado de autenticación
        if (onLoginSuccess) {
          onLoginSuccess();
        }
        navigate('/editor'); // Redirige al editor después de un login simulado
      } else {
        alert('Credenciales incorrectas (simulado).');
      }
    } else {
      if (password !== confirmPassword) {
        alert('Las contraseñas no coinciden.');
        return;
      }
      console.log('Intentando registrar usuario con:', { email, password });
      // Simulación de registro.
      const simulatedRegisterSuccess = true;
      if (simulatedRegisterSuccess) {
        alert('Registro simulado exitoso. Por favor, inicia sesión.');
        setIsLogin(true);
      } else {
        alert('Error en el registro (simulado).');
      }
    }
  };

  return (
    <div className={styles.container}>
      <div className={styles.card}>
        <h1 className={styles.title}>{isLogin ? 'Iniciar Sesión' : 'Registrarse'}</h1>
        <form onSubmit={handleSubmit} className={styles.form}>
          <div className={styles.formGroup}>
            <label htmlFor="email" className={styles.label}>Correo Electrónico:</label>
            <input
              type="email"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className={styles.input}
            />
          </div>
          <div className={styles.formGroup}>
            <label htmlFor="password" className={styles.label}>Contraseña:</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className={styles.input}
            />
          </div>
          {!isLogin && (
            <div className={styles.formGroup}>
              <label htmlFor="confirmPassword" className={styles.label}>Confirmar Contraseña:</label>
              <input
                type="password"
                id="confirmPassword"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                className={styles.input}
              />
            </div>
          )}
          <button type="submit" className={styles.button}>
            {isLogin ? 'Login' : 'Registrar'}
          </button>
        </form>
        <p className={styles.toggleText}>
          {isLogin ? '¿No tienes una cuenta?' : '¿Ya tienes una cuenta?'}
          <span onClick={handleToggleForm} className={styles.toggleLink}>
            {isLogin ? ' Regístrate aquí' : ' Inicia sesión aquí'}
          </span>
        </p>
      </div>
    </div>
  );
}

export default LoginPage;