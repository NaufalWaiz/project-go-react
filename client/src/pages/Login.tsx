import React, { useState } from 'react';
import axios from 'axios';
import './Login.css'; // Pastikan ini mengarah ke file CSS yang benar
import { useNavigate } from 'react-router-dom';

const LoginPage: React.FC = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const navigate = useNavigate();

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();

        try {
            const response = await axios.post('http://localhost:8081/login', {
                username,
                password,
            });

            if (response.status === 200) {
                const sessionKey = response.data.sessionKey;
                localStorage.setItem('sessionKey', sessionKey);
                navigate('/todo'); 
            }
        } catch (error) {
            if (axios.isAxiosError(error) && error.response) {
                setError(error.response.data.error || 'Invalid username or password');
            } else {
                setError('An unexpected error occurred');
            }
        }
    };

    return (
        <div className="login-container">
            <form className='login-form' onSubmit={handleSubmit}>
            <h2 className='login-title'>Login</h2>
                <div>
                    <input
                        type="text"
                        name='username'
                        placeholder='Username'
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        required
                        className='login-input'
                    />
                </div>
                <div>
                    <input
                        type="password"
                        name='password'
                        placeholder='Password'
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                        className='login-input'
                    />
                </div>
                {error && <p className="error-message">{error}</p>}
                <button type="submit" className='login-button'>Login</button>
            </form>
        </div>
    );
};

export default LoginPage;
