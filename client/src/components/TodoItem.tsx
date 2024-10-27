import { Badge, Box, Flex, Spinner, Text } from "@chakra-ui/react";
import { FaCheckCircle } from "react-icons/fa";
import { MdDelete } from "react-icons/md";
import { Todo } from "./TodoList";
import { useMutation, useQueryClient } from "@tanstack/react-query";

const BASE_URL = "http://localhost:5000/api";

const TodoItem = ({ todo }: { todo: Todo }) => {
    const queryClient = useQueryClient();
    const sessionKey = localStorage.getItem("sessionKey");  // Ambil session key dari localStorage

    const { mutate: updateTodo, isPending: isUpdating } = useMutation({
        mutationKey: ["updateTodo"],
        mutationFn: async () => {
            if (todo.completed) return alert("Todo is already completed");
            try {
                const res = await fetch(BASE_URL + `/todos/${todo.id}`, {
                    method: "PATCH",
                    headers: {
                        "Content-Type": "application/json",
                        ...(sessionKey && { "sessionKey": sessionKey }),
                    },
                    body: JSON.stringify({ completed: true }),
                });
    
                console.log("Response Status:", res.status);
                console.log("Response Headers:", res.headers.get("Content-Type"));
    
                // Read the response as text to check the body
                const textData = await res.text();
                console.log("Raw Response Text:", textData); // Log the raw response
    
                // Parse the text only if it's valid JSON
                const data = JSON.parse(textData);
                if (!res.ok) {
                    throw new Error(data.error || "Something went wrong");
                }
    
                return data; // Return the parsed data if successful
            } catch (error) {
                console.error("Fetch error:", error);
                throw error; // Ensure the error is thrown to be handled by the mutation
            }
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ["todos"] });
        },
    });        
        

    const { mutate: deleteTodo, isPending: isDeleting } = useMutation({
        mutationKey: ["deleteTodo"],
        mutationFn: async () => {
            try {
                const res = await fetch(BASE_URL + `/todos/${todo.id}`, {
                    method: "DELETE",
                    headers: {
                        ...(sessionKey && { "sessionKey": sessionKey }),  // Tambahkan session key di header jika ada
                    },
                });
                const data = await res.json();
                if (!res.ok) {
                    throw new Error(data.error || "Something went wrong");
                }
                return data;
            } catch (error) {
                console.error(error);
                throw error;
            }
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ["todos"] });
        },
    });

    return (
        <Flex gap={2} alignItems={"center"}>
            <Flex
                flex={1}
                alignItems={"center"}
                border={"1px"}
                borderColor={"gray.600"}
                p={2}
                borderRadius={"lg"}
                justifyContent={"space-between"}
            >
                <Text
                    color={todo.completed ? "green.200" : "yellow.100"}
                    textDecoration={todo.completed ? "line-through" : "none"}
                >
                    {todo.body}
                </Text>
                {todo.completed && (
                    <Badge ml='1' colorScheme='green'>
                        Done
                    </Badge>
                )}
                {!todo.completed && (
                    <Badge ml='1' colorScheme='yellow'>
                        In Progress
                    </Badge>
                )}
            </Flex>
            <Flex gap={2} alignItems={"center"}>
                <Box color={"green.500"} cursor={"pointer"} onClick={() => updateTodo()}>
                    {!isUpdating && <FaCheckCircle size={20} />}
                    {isUpdating && <Spinner size={"sm"} />}
                </Box>
                <Box color={"red.500"} cursor={"pointer"} onClick={() => deleteTodo()}>
                    {!isDeleting && <MdDelete size={25} />}
                    {isDeleting && <Spinner size={"sm"} />}
                </Box>
            </Flex>
        </Flex>
    );
};
export default TodoItem;
