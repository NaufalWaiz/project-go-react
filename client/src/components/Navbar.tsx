import { Box, Flex, Button, useColorModeValue, useColorMode, Text, Container } from "@chakra-ui/react";
import { IoMoon } from "react-icons/io5";
import { MdSunny } from "react-icons/md";

export default function Navbar() {
	const { colorMode, toggleColorMode } = useColorMode();

	return (
		<Container maxW={"900px"}>
			<Box bg={useColorModeValue("gray.400", "gray.700")} px={4} my={4} borderRadius={"5"}>
				<Flex h={16} alignItems={"center"} justifyContent={"space-between"}>
					{/* LEFT SIDE */}
					<Flex
						justifyContent={"center"}
						alignItems={"center"}
						gap={3}
						display={{ base: "none", sm: "flex" }}
					>
						<img src='/pelindo2.png' alt='logo' width={100} height={100} />
						<Text fontSize={"40"}></Text>
						<img src='/ILCS.png' alt='logo' width={100} height={100} />
					</Flex>

					{/* RIGHT SIDE */}
					<Flex alignItems={"center"} gap={3}>
						<Text fontSize={"lg"} fontWeight={500}>
							Task Management
						</Text>
						{/* Toggle Color Mode */}
						<Button onClick={toggleColorMode}>
							{colorMode === "light" ? <IoMoon /> : <MdSunny size={20} />}
						</Button>
					</Flex>
				</Flex>
			</Box>
		</Container>
	);
}