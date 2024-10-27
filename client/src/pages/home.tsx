import { Box, Button, Heading, Stack, Text } from '@chakra-ui/react';
import { useNavigate } from 'react-router-dom';
import React from 'react';
import './home.css';

const HomePage: React.FC = () => {
  const navigate = useNavigate();

  return (
    <Box 
      textAlign="center" 
      py={10} 
      px={6} 
      height="100vh" 
      display="flex" 
      flexDirection="column" 
      alignItems="center" 
      justifyContent="center" 
      backgroundColor="#c3c1fe"
    >
      <Heading className='title' as="h1" size="2xl" mb={6}>
        Welcome to Task Manager
      </Heading>
      <Text fontSize="xl" color="black" mb={8}>
        Manage your tasks efficiently and effortlessly
      </Text>

      <Stack spacing={4} direction="row" align="center">
        <Button 
          backgroundColor="#000010" 
          variant="solid" 
          size="lg" 
          onClick={() => navigate('/login')}
        >
          Login
        </Button>

        <Button 
          backgroundColor="#000010" 
          variant="solid" 
          size="lg" 
          onClick={() => navigate('/register')}
        >
          Register
        </Button>
      </Stack>
    </Box>
  );
};

export default HomePage;
