import React, { useState } from 'react';
import axios from 'axios';
import './Register.css';
import { useNavigate } from 'react-router-dom';

// Definisikan tipe untuk state
interface User {
    username: string;
    password: string;
    email: string;
}

const Register: React.FC = () => {
    const [user, setUser] = useState<User>({ username: '', password: '', email: '' });
    // Handle perubahan input
    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setUser({ ...user, [e.target.name]: e.target.value });
    };

    const navigate = useNavigate();

    // Handle submit
    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            await axios.post('http://localhost:8081/register', user);
            alert('User registered successfully!');
            navigate('/login');
        } catch (error) {
            console.error(error);
            alert('Error registering user');
        }
    };

    return (
        <div className="register-container">
            <form className="register-form" onSubmit={handleSubmit}>
                <h2 className="register-title">Register</h2>
                <input
                    type="text"
                    name="username"
                    placeholder="Username"
                    value={user.username}
                    onChange={handleChange}
                    required
                    className="register-input"
                />
                <input
                    type="password"
                    name="password"
                    placeholder="Password"
                    value={user.password}
                    onChange={handleChange}
                    required
                    className="register-input"
                />
                <input
                    type="text"
                    name="email"
                    placeholder="Email"
                    value={user.email}
                    onChange={handleChange}
                    required
                    className="register-input"
                />
                
                <button type="submit" className="register-button">Register</button>
            </form>
        </div>
    );
};

export default Register;

