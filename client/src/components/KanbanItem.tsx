import {useRef} from 'react';
import {useDrag} from 'react-dnd';

interface KanbanItemProps {
  id: number;
  children: React.ReactNode;
}

const KanbanItem: React.FC<KanbanItemProps> = ({id, children}) => {
  const ref = useRef<HTMLDivElement>(null);
  const [{isDragging}, drag] = useDrag({
    type: 'card',
    item: {id},
    collect: monitor => ({
      isDragging: monitor.isDragging(),
    }),
  });
  const opacity = isDragging ? 0 : 1;
  drag(ref);
  return (
    <div ref={ref} style={{opacity}}>
      {children}
    </div>
  );
};

export default KanbanItem;
