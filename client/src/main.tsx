import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import { ChakraProvider } from '@chakra-ui/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import TodoKanban from './pages/TodoKanban';
import LoginPage from './pages/Login';
import RegisterPage from './pages/Register';
import TodoPage from './Todo';
import HomePage from './pages/home';

const router = createBrowserRouter([
  {
    path: "/login",
    element: <LoginPage />
  },
  {
    path: "/",
    element: <HomePage />
  },
  {
    path: "/register",
    element: <RegisterPage />
  },
  {
    path: "/todo",
    element: <TodoPage />
  },
  {
    path: "/todokanban",
    element: <TodoKanban />
  }
]);

const queryClient = new QueryClient();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ChakraProvider>
        <RouterProvider router={router} />
      </ChakraProvider>
    </QueryClientProvider>
  </StrictMode>
);