import React, { useState, useEffect, useCallback, useRef } from "react";
import { DndProvider, useDrag, useDrop } from "react-dnd";
import { HTML5Backend } from "react-dnd-html5-backend";
import update from "immutability-helper";
import KanbanItem from "../components/KanbanItem";
import { Button } from "@chakra-ui/react";
import { Link } from "react-router-dom";


const BASE_URL = "http://localhost:5000/api";

// No longer need a static tasksList
const channels = ["new", "done"];
const labelsMap = {
  new: "In Progress",
  done: "Done"
};

const classes = {
  board: {
    display: "flex",
    margin: "0 auto",
    marginLeft: "340px",
    width: "90vw",
    fontFamily: 'Arial, "Helvetica Neue", sans-serif',
  },
  column: {
    minWidth: 200,
    width: "25vw",
    height: "80vh",
    margin: "0 auto",
    backgroundColor: "#000c19",
  },
  columnHead: {
    textAlign: "center",
    padding: 10,
    fontSize: "1.2em",
    backgroundColor: "#00254d",
  },
  item: {
    padding: 10,
    margin: 10,
    fontSize: "0.8em",
    cursor: "pointer",
    backgroundColor: "white",
    color: "black",
    borderRadius: "5px",
  },
  button: {
    width:"15%",
    padding:"10px",
    marginBottom:"20px",
    marginLeft:"575px",
    marginRight:"auto",
    backgroundColor:"#28a745",
    border:"none",
    borderRadius:"4px",
    color:"white",
    fontSize:"16px",
    cursor:"pointer",
    transition:"background-color 0.3s ease",
  },
};

const Kanban = () => {
  const [tasks, setTaskStatus] = useState([]);
  
  // Fetch the tasks from the backend on component mount
  useEffect(() => {
    const fetchTasks = async () => {
      try {
        const sessionKey = localStorage.getItem("sessionKey"); // Assuming session key is stored in localStorage
  
        const response = await fetch(BASE_URL + `/todos`, {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
            "sessionKey": `${sessionKey}`, // Assuming your backend expects the session key in the Authorization header
          },
        });
  
        if (response.ok) {
          const data = await response.json();

          const newData = data.map((task) => {
            return {
              ...task,
              status: task.completed ? "done" : "new"
            }
          });

          setTaskStatus(newData);
        } else if (response.status === 401) {
          console.error("Unauthorized: Invalid session key");
        } else {
          console.error("Failed to fetch tasks");
        }
      } catch (error) {
        console.error("Error fetching tasks:", error);
      }
    };
  
    fetchTasks();
  }, []);
  

  // Handle changing task status
  const changeTaskStatus = useCallback(
    (id, status) => {
      let task = tasks.find((task) => task.id === id);
      const taskIndex = tasks.indexOf(task);
      task = { ...task, status };

      updateStatus(task); // Update task status in the backend
      console.log(task)
      let newTasks = update(tasks, {
        [taskIndex]: { $set: task },
      });
      setTaskStatus(newTasks);
    },
    [tasks]
  );

  const updateStatus = async (task) => {
    try {
      const sessionKey = localStorage.getItem("sessionKey"); // Assuming session key is stored in localStorage
      const response = await fetch(BASE_URL + `/todos/${task.id}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "sessionKey": `${sessionKey}`, // Assuming your backend expects the session key in the Authorization header
        },
        body: JSON.stringify({ completed: task.status === "done" }),
      });
    } catch (error) {
      console.error("Error updating task:", error);
    }
  }

  return (
    <main>
      <header style={{ marginLeft: "600px", fontSize: "25px", marginBottom: "20px", marginTop: "20px" }}>
        Kanban Board
      </header>
      <Link to="/todo">
      <button style={classes.button}>List View</button> </Link>
      <DndProvider backend={HTML5Backend}>
        <section style={classes.board}>
          {channels.map((channel) => (
            <KanbanColumn key={channel} status={channel} changeTaskStatus={changeTaskStatus}>
              <div style={classes.column}>
                <div style={classes.columnHead}>{labelsMap[channel]}</div>
                <div>
                  {tasks
                    .filter((item) => item.status === channel)
                    .map((item) => (
                      <KanbanItem key={item.id} id={item.id}>
                        <div style={classes.item}>{item.body}</div>
                      </KanbanItem>
                    ))}
                </div>
              </div>
            </KanbanColumn>
          ))}
        </section>
      </DndProvider>
    </main>
  );
};

export default Kanban;

const KanbanColumn = ({ status, changeTaskStatus, children }) => {
  const ref = useRef(null);
  const [, drop] = useDrop({
    accept: "card",
    drop(item) {
      changeTaskStatus(item.id, status);
    },
  });
  drop(ref);
  return <div ref={ref}>{children}</div>;
};
