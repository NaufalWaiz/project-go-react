import { Flex, Spinner, Stack, Text } from "@chakra-ui/react";

import TodoItem from "./TodoItem";
import { useQuery } from "@tanstack/react-query";

const BASE_URL = "http://localhost:5000/api";  // Update this to reflect the correct URL

export type Todo = {
	id: number;
	body: string;
	completed: boolean;
};

const TodoList = () => {
    // Ambil sessionKey dari localStorage
	const sessionKey = localStorage.getItem('sessionKey');

	const { data, isLoading } = useQuery({
        queryKey: ['todos'],
        queryFn: async () => {
            if (!sessionKey) {
                throw new Error("Missing session key");
            }

            const res = await fetch(BASE_URL + `/todos`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'sessionKey': sessionKey, // Kirim session key di header
                },
            });
            if (!res.ok) {
                throw new Error('Failed to fetch todos');
            }

            return res.json();
        },
    });

	return (
		<>
			<Text
				fontSize={"4xl"}
				textTransform={"uppercase"}
				fontWeight={"bold"}
				textAlign={"center"}
				my={2}
				bgGradient='linear(to-l, #0b85f8, #00ffff)'
				bgClip='text'
				marginRight={"4rem"}
			>
				Today Task
			</Text>
			{isLoading && (
				<Flex justifyContent={"center"} my={4}>
					<Spinner size={"xl"} />
				</Flex>
			)}
			{!isLoading && data?.length === 0 && (
				<Stack alignItems={"center"} gap='3'>
					<Text fontSize={"xl"} textAlign={"center"} color={"gray.500"}>
						Semua Tugas Selesai! 😃
					</Text>
					<img src='/pelindologo.png' alt='Go logo' width={50} height={50} />
				</Stack>
			)}
			<Stack gap={3}>
				{data?.map((todo: Todo) => (
					<TodoItem key={todo.id} todo={todo} />
				))}
			</Stack>
		</>
	);
};
export default TodoList;