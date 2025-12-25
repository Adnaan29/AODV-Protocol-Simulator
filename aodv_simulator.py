import pygame
import random
import math
import time
import os
import struct
import datetime
from collections import deque, defaultdict
from enum import Enum
import subprocess
import sys

# Initialize Pygame
pygame.init()

# Constants
WIDTH, HEIGHT = 1600, 900
NETWORK_WIDTH = 1300
NODE_RADIUS = 14
PACKET_RADIUS = 7
NODE_COLOR = (70, 130, 180)
RREQ_COLOR = (255, 140, 0)
RREP_COLOR = (30, 144, 255)
DATA_COLOR = (50, 255, 100)
RERR_COLOR = (255, 50, 50)
BACKGROUND = (10, 20, 30)
GRID_COLOR = (25, 35, 45)
TEXT_COLOR = (240, 240, 240)
HIGHLIGHT_COLOR = (255, 50, 50)
RANGE_COLOR = (30, 60, 90)
UI_COLOR = (25, 35, 50)
BUTTON_COLOR = (60, 100, 180)
BUTTON_HOVER_COLOR = (80, 120, 200)
TOGGLE_ON_COLOR = (50, 200, 100)
TOGGLE_OFF_COLOR = (200, 60, 60)
INTRO_BG = (15, 25, 40)
COLUMN_BG = (25, 35, 50, 180)
SCROLLBAR_COLOR = (100, 120, 140)
SCROLLBAR_HOVER = (120, 140, 160)

class GameState(Enum):
    INTRODUCTION = 1
    SIMULATION = 2

class PacketType(Enum):
    RREQ = 1
    RREP = 2
    DATA = 3
    RERR = 4

class PCAPPacket:
    """Class to store packet data for PCAP generation"""
    def __init__(self, timestamp, src_node, dst_node, packet_type, hop_count, path=None):
        self.timestamp = timestamp
        self.src_node = src_node
        self.dst_node = dst_node
        self.packet_type = packet_type
        self.hop_count = hop_count
        self.path = path or []
        self.seq_num = random.randint(1, 1000)
        self.ttl = 64
        
    def to_bytes(self):
        """Convert packet to bytes for PCAP (simplified version)"""
        # Simplified packet structure for demonstration
        # In real implementation, you'd use scapy or proper AODV packet format
        packet_data = f"AODV|{self.packet_type.name}|Src:{self.src_node}|Dst:{self.dst_node}|Hops:{self.hop_count}|Seq:{self.seq_num}"
        return packet_data.encode('utf-8')
    
    def get_wireshark_info(self):
        """Get display string for Wireshark"""
        type_str = self.packet_type.name
        if self.packet_type == PacketType.RREQ:
            type_str = "Route Request"
        elif self.packet_type == PacketType.RREP:
            type_str = "Route Reply"
        elif self.packet_type == PacketType.DATA:
            type_str = "Data"
        elif self.packet_type == PacketType.RERR:
            type_str = "Route Error"
        
        return f"AODV {type_str}: Node {self.src_node} -> Node {self.dst_node} (Hops: {self.hop_count}, Seq: {self.seq_num})"

class AnimatedPacket:
    def __init__(self, packet_id, packet_type, path, base_speed=0.8, from_node=None, to_node=None):
        self.id = packet_id
        self.type = packet_type
        self.path = path
        self.current_node_index = 0
        self.progress = 0.0
        self.base_speed = base_speed
        self.completed = False
        self.color = self.get_color()
        self.from_node = from_node
        self.to_node = to_node
        self.hop_count = len(path) - 1 if path else 0
        self.timestamp = time.time()
        
    def get_color(self):
        if self.type == PacketType.RREQ:
            return RREQ_COLOR
        elif self.type == PacketType.RREP:
            return RREP_COLOR
        elif self.type == PacketType.DATA:
            return DATA_COLOR
        elif self.type == PacketType.RERR:
            return RERR_COLOR
        return (255, 255, 255)
    
    def update(self, delta_time, speed_multiplier=1.0):
        if self.completed:
            return False
            
        actual_speed = self.base_speed * speed_multiplier
        self.progress += actual_speed * delta_time
        
        if self.progress >= 1.0:
            self.current_node_index += 1
            self.progress = 0.0
            
            if self.current_node_index >= len(self.path) - 1:
                self.completed = True
                self.progress = 1.0
                return True
        return False
    
    def get_current_position(self, nodes):
        if self.current_node_index >= len(self.path) - 1:
            end_node = nodes[self.path[-1]]
            return (end_node.x, end_node.y)
            
        start_node = nodes[self.path[self.current_node_index]]
        end_node = nodes[self.path[self.current_node_index + 1]]
        
        x = start_node.x + (end_node.x - start_node.x) * self.progress
        y = start_node.y + (end_node.y - start_node.y) * self.progress
        
        return (int(x), int(y))
    
    def draw(self, screen, nodes):
        pos = self.get_current_position(nodes)
        if pos:
            pygame.draw.circle(screen, self.color, pos, PACKET_RADIUS)
            pygame.draw.circle(screen, (255, 255, 255), pos, PACKET_RADIUS, 1)

class Node:
    def __init__(self, id, x, y):
        self.id = id
        self.x = x
        self.y = y
        self.vx = 0
        self.vy = 0
        self.neighbors = []
        self.original_neighbors = []
        self.routing_table = {}
        self.sequence_number = 0
        self.color = NODE_COLOR
        self.active = True
        self.communication_range = 130
        self.rreq_seen = set()
        self.is_moving = False
        self.mac_address = f"00:1A:2B:3C:{id:02X}:{id:02X}"
        
    def distance_to(self, other_node):
        return math.sqrt((self.x - other_node.x)**2 + (self.y - other_node.y)**2)
    
    def add_neighbor(self, neighbor):
        if neighbor not in self.neighbors:
            self.neighbors.append(neighbor)
        if neighbor not in self.original_neighbors:
            self.original_neighbors.append(neighbor)
    
    def update_position(self, delta_time):
        if not self.is_moving:
            return
            
        self.x += self.vx * delta_time * 8
        self.y += self.vy * delta_time * 8
        
        margin = 50
        if self.x < margin or self.x > NETWORK_WIDTH - margin:
            self.vx *= -1
        if self.y < margin or self.y > HEIGHT - margin:
            self.vy *= -1
            
        self.x = max(margin, min(NETWORK_WIDTH - margin, self.x))
        self.y = max(margin, min(HEIGHT - margin, self.y))
    
    def start_moving(self):
        self.is_moving = True
        self.vx = random.uniform(-0.5, 0.5)
        self.vy = random.uniform(-0.5, 0.5)
    
    def stop_moving(self):
        self.is_moving = False
        self.vx = 0
        self.vy = 0
    
    def update_neighbors(self, all_nodes):
        if not self.is_moving:
            return
            
        self.neighbors = []
        for node in all_nodes:
            if node != self and self.distance_to(node) <= self.communication_range:
                self.neighbors.append(node)
    
    def draw(self, screen, font, selected=False, is_source=False, is_dest=False):
        if is_source or is_dest:
            range_surface = pygame.Surface((self.communication_range * 2, self.communication_range * 2), pygame.SRCALPHA)
            pygame.draw.circle(range_surface, (*RANGE_COLOR, 20), 
                             (self.communication_range, self.communication_range), 
                             self.communication_range)
            screen.blit(range_surface, (self.x - self.communication_range, self.y - self.communication_range))
        
        if is_source:
            color = (50, 205, 50)
        elif is_dest:
            color = (220, 60, 60)
        elif selected:
            color = (255, 255, 100)
        else:
            color = self.color
            
        pygame.draw.circle(screen, color, (self.x, self.y), NODE_RADIUS)
        pygame.draw.circle(screen, (255, 255, 255), (self.x, self.y), NODE_RADIUS, 1)
        
        text_surface = font.render(str(self.id), True, TEXT_COLOR)
        text_width = text_surface.get_width()
        
        if text_width < NODE_RADIUS * 2 or is_source or is_dest:
            text_rect = text_surface.get_rect(center=(self.x, self.y))
            screen.blit(text_surface, text_rect)

class Button:
    def __init__(self, x, y, width, height, text, font, color=BUTTON_COLOR, hover_color=BUTTON_HOVER_COLOR):
        self.rect = pygame.Rect(x, y, width, height)
        self.text = text
        self.font = font
        self.color = color
        self.hover_color = hover_color
        self.hovered = False
        
    def draw(self, screen):
        color = self.hover_color if self.hovered else self.color
        pygame.draw.rect(screen, color, self.rect, border_radius=12)
        pygame.draw.rect(screen, (220, 220, 220), self.rect, 3, border_radius=12)
        
        text_surface = self.font.render(self.text, True, TEXT_COLOR)
        text_rect = text_surface.get_rect(center=self.rect.center)
        screen.blit(text_surface, text_rect)
        
    def is_hovered(self, pos):
        self.hovered = self.rect.collidepoint(pos)
        return self.hovered
        
    def is_clicked(self, pos, event):
        if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
            return self.rect.collidepoint(pos)
        return False

class ToggleButton:
    def __init__(self, x, y, width, height, text, font, initial_state=False):
        self.rect = pygame.Rect(x, y, width, height)
        self.text = text
        self.font = font
        self.state = initial_state
        self.hovered = False
        
    def draw(self, screen):
        color = TOGGLE_ON_COLOR if self.state else TOGGLE_OFF_COLOR
        pygame.draw.rect(screen, color, self.rect, border_radius=4)
        pygame.draw.rect(screen, (200, 200, 200), self.rect, 2, border_radius=4)
        
        state_text = "ON" if self.state else "OFF"
        text_surface = self.font.render(f"{state_text}", True, TEXT_COLOR)
        text_rect = text_surface.get_rect(center=self.rect.center)
        screen.blit(text_surface, text_rect)
        
    def is_hovered(self, pos):
        self.hovered = self.rect.collidepoint(pos)
        return self.hovered
        
    def is_clicked(self, pos, event):
        if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
            if self.rect.collidepoint(pos):
                self.state = not self.state
                return True
        return False

class InputBox:
    def __init__(self, x, y, width, height, font, text='15'):
        self.rect = pygame.Rect(x, y, width, height)
        self.text = text
        self.font = font
        self.active = False
        
    def handle_event(self, event):
        if event.type == pygame.MOUSEBUTTONDOWN:
            self.active = self.rect.collidepoint(event.pos)
        if event.type == pygame.KEYDOWN and self.active:
            if event.key == pygame.K_RETURN:
                self.active = False
            elif event.key == pygame.K_BACKSPACE:
                self.text = self.text[:-1]
            else:
                if event.unicode.isdigit() and len(self.text) < 3:
                    self.text += event.unicode
        return self.text
        
    def draw(self, screen):
        color = (100, 150, 200) if self.active else (80, 100, 120)
        pygame.draw.rect(screen, color, self.rect, border_radius=4)
        pygame.draw.rect(screen, (200, 200, 200), self.rect, 2, border_radius=4)
        
        text_surface = self.font.render(self.text, True, TEXT_COLOR)
        screen.blit(text_surface, (self.rect.x + 8, self.rect.y + (self.rect.height - text_surface.get_height()) // 2))

class Slider:
    def __init__(self, x, y, width, height, min_val, max_val, initial_val, font, label):
        self.rect = pygame.Rect(x, y, width, height)
        self.min_val = min_val
        self.max_val = max_val
        self.value = initial_val
        self.dragging = False
        self.font = font
        self.label = label
        
    def handle_event(self, event):
        if event.type == pygame.MOUSEBUTTONDOWN:
            if self.rect.collidepoint(event.pos):
                self.dragging = True
                self.update_value(event.pos[0])
        elif event.type == pygame.MOUSEBUTTONUP:
            self.dragging = False
        elif event.type == pygame.MOUSEMOTION and self.dragging:
            self.update_value(event.pos[0])
            
    def update_value(self, x_pos):
        relative_x = max(0, min(x_pos - self.rect.x, self.rect.width))
        self.value = self.min_val + (relative_x / self.rect.width) * (self.max_val - self.min_val)
        
    def draw(self, screen):
        pygame.draw.rect(screen, (60, 70, 80), self.rect, border_radius=3)
        pygame.draw.rect(screen, (100, 110, 120), self.rect, 2, border_radius=3)
        
        handle_x = self.rect.x + int((self.value - self.min_val) / (self.max_val - self.min_val) * self.rect.width)
        handle_rect = pygame.Rect(handle_x - 5, self.rect.y - 2, 10, self.rect.height + 4)
        pygame.draw.rect(screen, BUTTON_HOVER_COLOR if self.dragging else BUTTON_COLOR, handle_rect, border_radius=5)
        pygame.draw.rect(screen, (200, 200, 200), handle_rect, 2, border_radius=5)
        
        label_text = self.font.render(f"{self.label}: {self.value:.1f}x", True, TEXT_COLOR)
        screen.blit(label_text, (self.rect.x, self.rect.y - 20))

class EventLog:
    def __init__(self, x, y, width, height, font, max_events=20):  # Increased max_events
        self.rect = pygame.Rect(x, y, width, height)
        self.font = font
        self.events = deque(maxlen=max_events)
        self.max_events = max_events
        self.scroll_offset = 0
        self.scrollbar_rect = pygame.Rect(x + width - 10, y + 40, 8, height - 50)
        self.scrollbar_dragging = False
        self.scrollbar_handle_height = 50
        self.total_events = 0
        
    def add_event(self, event_text, packet_type=None, from_node=None, to_node=None, hop_count=None):
        timestamp = time.strftime("%H:%M:%S")
        event_details = f"[{timestamp}] {event_text}"
        
        if packet_type:
            type_str = ""
            if packet_type == PacketType.RREQ:
                type_str = "RREQ"
            elif packet_type == PacketType.RREP:
                type_str = "RREP"
            elif packet_type == PacketType.DATA:
                type_str = "DATA"
            elif packet_type == PacketType.RERR:
                type_str = "RERR"
            
            event_details = f"[{timestamp}] {type_str}: {event_text}"
            
            if from_node is not None and to_node is not None:
                event_details += f" (Node {from_node} → Node {to_node})"
            
            if hop_count is not None:
                event_details += f" [Hops: {hop_count}]"
        
        self.events.append(event_details)
        self.total_events += 1
        
    def handle_event(self, event, mouse_pos):
        if event.type == pygame.MOUSEBUTTONDOWN:
            if self.scrollbar_rect.collidepoint(mouse_pos):
                self.scrollbar_dragging = True
                return True
        elif event.type == pygame.MOUSEBUTTONUP:
            self.scrollbar_dragging = False
        elif event.type == pygame.MOUSEMOTION and self.scrollbar_dragging:
            relative_y = mouse_pos[1] - self.rect.y - 40
            max_scroll = max(0, len(self.events) * 25 - (self.rect.height - 50))
            self.scroll_offset = max(0, min(max_scroll, 
                                          (relative_y / (self.rect.height - 50)) * max_scroll))
            return True
        elif event.type == pygame.MOUSEWHEEL:
            max_scroll = max(0, len(self.events) * 25 - (self.rect.height - 50))
            self.scroll_offset = max(0, min(max_scroll, self.scroll_offset - event.y * 20))
            return True
        return False
        
    def draw(self, screen):
        pygame.draw.rect(screen, (20, 30, 40), self.rect)
        pygame.draw.rect(screen, (60, 80, 100), self.rect, 2)
        
        title_font = pygame.font.SysFont('Arial', 16, bold=True)
        title = title_font.render("EVENTS LOG", True, (200, 200, 255))
        screen.blit(title, (self.rect.x + 10, self.rect.y + 12))
        
        pygame.draw.line(screen, (60, 80, 100), 
                        (self.rect.x + 10, self.rect.y + 40),
                        (self.rect.x + self.rect.width - 10, self.rect.y + 40), 1)
        
        # Draw scrollable area
        clip_rect = pygame.Rect(self.rect.x + 5, self.rect.y + 45, 
                               self.rect.width - 20, self.rect.height - 50)
        screen.set_clip(clip_rect)
        
        visible_events = list(self.events)
        for i, event in enumerate(visible_events):
            y_pos = self.rect.y + 50 + i * 25 - self.scroll_offset
            
            # Only draw if within visible area
            if y_pos < self.rect.y + self.rect.height - 10 and y_pos > self.rect.y + 40:
                color = TEXT_COLOR
                if "RREQ" in event:
                    color = RREQ_COLOR
                elif "RREP" in event:
                    color = RREP_COLOR
                elif "DATA" in event:
                    color = DATA_COLOR
                elif "RERR" in event:
                    color = RERR_COLOR
                
                # Truncate long text
                max_width = self.rect.width - 30
                event_text = event
                while self.font.size(event_text)[0] > max_width and len(event_text) > 20:
                    event_text = event_text[:-4] + "..."
                
                text = self.font.render(event_text, True, color)
                screen.blit(text, (self.rect.x + 10, y_pos))
        
        screen.set_clip(None)
        
        # Draw scrollbar if needed
        max_scroll = max(0, len(self.events) * 25 - (self.rect.height - 50))
        if max_scroll > 0:
            scrollbar_color = SCROLLBAR_HOVER if self.scrollbar_dragging else SCROLLBAR_COLOR
            
            # Calculate handle position
            handle_y = self.rect.y + 40 + (self.scroll_offset / max_scroll) * (self.rect.height - 50 - self.scrollbar_handle_height)
            handle_rect = pygame.Rect(self.scrollbar_rect.x, handle_y, 
                                     self.scrollbar_rect.width, self.scrollbar_handle_height)
            
            pygame.draw.rect(screen, (40, 50, 60), self.scrollbar_rect)
            pygame.draw.rect(screen, scrollbar_color, handle_rect, border_radius=3)
            pygame.draw.rect(screen, (150, 150, 150), handle_rect, 1, border_radius=3)

class AODVSimulator:
    def __init__(self):
        self.nodes = []
        self.active_packets = []
        self.packet_queue = deque()
        self.num_nodes = 15
        self.source = None
        self.destination = None
        self.simulation_running = False
        self.simulation_complete = False
        self.packet_counter = 0
        self.final_path = []
        self.discovered_paths = []
        self.all_discovered_paths_to_dest = []
        self.animation_speed = 1.0
        self.rreq_broadcast_id = 0
        self.best_path_hop_count = float('inf')
        self.route_established = False
        self.mobility_enabled = False
        self.event_log = None
        self.pcap_packets = []  # Store packets for PCAP generation
        self.pcap_enabled = False
        self.setup_nodes()
        
    def setup_nodes(self):
        self.nodes = []
        margin = 60
        
        nodes_created = 0
        max_attempts = self.num_nodes * 10
        
        while nodes_created < self.num_nodes and max_attempts > 0:
            x = random.randint(margin, NETWORK_WIDTH - margin)
            y = random.randint(margin, HEIGHT - margin)
            
            too_close = False
            for node in self.nodes:
                if math.sqrt((x - node.x)**2 + (y - node.y)**2) < 40:
                    too_close = True
                    break
            
            if not too_close:
                self.nodes.append(Node(nodes_created, x, y))
                nodes_created += 1
            max_attempts -= 1
        
        if nodes_created < self.num_nodes:
            remaining_nodes = self.num_nodes - nodes_created
            for i in range(remaining_nodes):
                x = random.randint(margin, NETWORK_WIDTH - margin)
                y = random.randint(margin, HEIGHT - margin)
                self.nodes.append(Node(nodes_created + i, x, y))
        
        connection_count = 0
        for i, node1 in enumerate(self.nodes):
            for j, node2 in enumerate(self.nodes):
                if i != j:
                    distance = node1.distance_to(node2)
                    if distance <= node1.communication_range:
                        node1.add_neighbor(node2)
                        connection_count += 1
        
        extra_connections = 0
        for i in range(len(self.nodes)):
            for j in range(i + 1, len(self.nodes)):
                if i != j:
                    node1 = self.nodes[i]
                    node2 = self.nodes[j]
                    distance = node1.distance_to(node2)
                    if (node1.communication_range * 0.8 <= distance <= node1.communication_range * 1.2 and
                        random.random() < 0.3):
                        node1.add_neighbor(node2)
                        node2.add_neighbor(node1)
                        extra_connections += 2
        
        print(f"Created {len(self.nodes)} nodes with {connection_count} basic + {extra_connections} extra connections")
    
    def add_pcap_packet(self, packet_type, from_node, to_node, hop_count, path=None):
        """Add a packet to PCAP recording"""
        if not self.pcap_enabled:
            return
            
        pcap_packet = PCAPPacket(
            timestamp=time.time(),
            src_node=from_node,
            dst_node=to_node,
            packet_type=packet_type,
            hop_count=hop_count,
            path=path
        )
        self.pcap_packets.append(pcap_packet)
    
    def generate_pcap_file(self):
        """Generate a PCAP file from captured packets"""
        if not self.pcap_packets:
            return None
            
        try:
            # Create a simple text-based representation that can be parsed
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"aodv_simulation_{timestamp}.pcap.txt"
            
            with open(filename, 'w') as f:
                f.write("# AODV Simulation PCAP Dump\n")
                f.write("# Generated by AODV Simulator\n")
                f.write(f"# Source: {self.source}, Destination: {self.destination}\n")
                f.write(f"# Total Packets: {len(self.pcap_packets)}\n")
                f.write("# Timestamp,Protocol,Source,Destination,Info\n")
                
                for i, packet in enumerate(self.pcap_packets):
                    timestamp_str = datetime.datetime.fromtimestamp(packet.timestamp).strftime("%H:%M:%S.%f")[:-3]
                    info = packet.get_wireshark_info()
                    f.write(f"{timestamp_str},AODV,Node_{packet.src_node},Node_{packet.dst_node},\"{info}\"\n")
            
            print(f"PCAP file generated: {filename}")
            
            # Create a batch file to open in Wireshark
            batch_content = f"""@echo off
echo AODV Simulation PCAP File
echo =========================
echo.
echo File: {filename}
echo Total Packets: {len(self.pcap_packets)}
echo.
echo This file contains AODV protocol packets that can be analyzed.
echo Open this file in Wireshark or any text editor to view the packet details.
echo.
pause
"""
            
            batch_filename = f"open_{timestamp}.bat"
            with open(batch_filename, 'w') as f:
                f.write(batch_content)
            
            return filename
            
        except Exception as e:
            print(f"Error generating PCAP file: {e}")
            return None
    
    def enable_pcap(self, enabled=True):
        """Enable or disable PCAP recording"""
        self.pcap_enabled = enabled
        if enabled:
            self.pcap_packets = []
            if self.event_log:
                self.event_log.add_event("PCAP recording ENABLED")
        else:
            if self.event_log:
                self.event_log.add_event("PCAP recording DISABLED")
    
    def toggle_mobility(self):
        self.mobility_enabled = not self.mobility_enabled
        for node in self.nodes:
            if self.mobility_enabled:
                node.start_moving()
            else:
                node.stop_moving()
        
        if self.event_log:
            if self.mobility_enabled:
                self.event_log.add_event("Node mobility ENABLED")
            else:
                self.event_log.add_event("Node mobility DISABLED")
    
    def reset_simulation(self):
        self.active_packets = []
        self.packet_queue = deque()
        self.simulation_running = False
        self.simulation_complete = False
        self.final_path = []
        self.discovered_paths = []
        self.all_discovered_paths_to_dest = []
        self.best_path_hop_count = float('inf')
        self.route_established = False
        self.packet_counter = 0
        self.pcap_packets = []
        for node in self.nodes:
            node.rreq_seen.clear()
            node.color = NODE_COLOR
        if self.event_log:
            self.event_log.events.clear()
            self.event_log.scroll_offset = 0
            self.event_log.total_events = 0
    
    def start_simulation(self):
        if self.source is None or self.destination is None:
            return
            
        self.reset_simulation()
        self.simulation_running = True
        self.enable_pcap(True)  # Enable PCAP recording for this simulation
        if self.event_log:
            self.event_log.add_event(f"Simulation: {self.source} → {self.destination}")
            self.event_log.add_event(f"Network: {len(self.nodes)} nodes")
            self.event_log.add_event("PCAP recording started")
        self.start_rreq_flooding()
    
    def start_rreq_flooding(self):
        self.rreq_broadcast_id = self.packet_counter
        self.packet_counter += 1
        
        source_node = self.nodes[self.source]
        for neighbor in source_node.neighbors:
            path = [self.source, neighbor.id]
            packet = AnimatedPacket(self.packet_counter, PacketType.RREQ, path, base_speed=0.8, 
                                  from_node=self.source, to_node=neighbor.id)
            self.packet_queue.append(packet)
            self.packet_counter += 1
            self.discovered_paths.append(path)
            source_node.rreq_seen.add((self.source, self.rreq_broadcast_id))
            
            if self.event_log:
                self.event_log.add_event("Route Request sent", PacketType.RREQ, self.source, neighbor.id, 1)
            
            # Record in PCAP
            self.add_pcap_packet(PacketType.RREQ, self.source, neighbor.id, 1, path)
    
    def process_packet_completion(self, packet):
        current_node_id = packet.path[-1]
        
        if packet.type == PacketType.RREQ:
            if current_node_id == self.destination:
                self.all_discovered_paths_to_dest.append(packet.path)
                hop_count = len(packet.path) - 1
                
                if hop_count < self.best_path_hop_count:
                    self.best_path_hop_count = hop_count
                    self.final_path = packet.path
                    
                    if self.event_log:
                        self.event_log.add_event(f"Better path found", PacketType.RREQ, 
                                               packet.path[0], self.destination, hop_count)
                    
                    self.send_rrep_back(packet.path)
                
                if len(self.all_discovered_paths_to_dest) >= 5 or self.best_path_hop_count <= 2:
                    self.route_established = True
                    if self.event_log:
                        self.event_log.add_event(f"Stopping RREQ - Found {len(self.all_discovered_paths_to_dest)} paths")
                    return
                
            current_node = self.nodes[current_node_id]
            for neighbor in current_node.neighbors:
                if neighbor.id not in packet.path:
                    rreq_key = (self.source, self.rreq_broadcast_id)
                    if rreq_key not in neighbor.rreq_seen:
                        new_path = packet.path + [neighbor.id]
                        new_packet = AnimatedPacket(self.packet_counter, PacketType.RREQ, new_path, base_speed=0.8,
                                                  from_node=current_node_id, to_node=neighbor.id)
                        self.packet_queue.append(new_packet)
                        self.packet_counter += 1
                        self.discovered_paths.append(new_path)
                        neighbor.rreq_seen.add(rreq_key)
                        
                        if self.event_log:
                            hop_count = len(new_path) - 1
                            self.event_log.add_event("Route Request forwarded", PacketType.RREQ, 
                                                   current_node_id, neighbor.id, hop_count)
                        
                        # Record in PCAP
                        self.add_pcap_packet(PacketType.RREQ, current_node_id, neighbor.id, hop_count, new_path)
        
        elif packet.type == PacketType.RREP:
            if current_node_id == self.source:
                if self.event_log:
                    self.event_log.add_event("Route Reply reached source", PacketType.RREP)
                self.send_data_packet()
            else:
                if len(packet.path) > 1:
                    from_node = packet.path[-2]
                    to_node = packet.path[-1]
                    if self.event_log:
                        self.event_log.add_event("Route Reply forwarded", PacketType.RREP, from_node, to_node)
                    
                    # Record in PCAP
                    self.add_pcap_packet(PacketType.RREP, from_node, to_node, len(packet.path)-1, packet.path)
        
        elif packet.type == PacketType.DATA:
            if current_node_id == self.destination:
                if self.event_log:
                    self.event_log.add_event("Data reached destination!", PacketType.DATA)
                self.simulation_complete = True
                self.simulation_running = False
            else:
                if len(packet.path) > 1:
                    from_node = packet.path[-2]
                    to_node = packet.path[-1]
                    if self.event_log:
                        self.event_log.add_event("Data forwarded", PacketType.DATA, from_node, to_node)
                    
                    # Record in PCAP
                    self.add_pcap_packet(PacketType.DATA, from_node, to_node, len(packet.path)-1, packet.path)
        
        elif packet.type == PacketType.RERR:
            if self.event_log:
                self.event_log.add_event("Route Error processed", PacketType.RERR, 
                                       packet.from_node, packet.to_node)
            
            # Record in PCAP
            self.add_pcap_packet(PacketType.RERR, packet.from_node, packet.to_node, 1, [packet.from_node, packet.to_node])
            
            if current_node_id == self.source:
                if self.event_log:
                    self.event_log.add_event("Initiating new route discovery due to RERR")
                self.start_rreq_flooding()
    
    def send_rrep_back(self, path):
        rrep_path = list(reversed(path))
        rrep_packet = AnimatedPacket(self.packet_counter, PacketType.RREP, rrep_path, base_speed=0.8)
        self.packet_queue.append(rrep_packet)
        self.packet_counter += 1
        
        if self.event_log:
            self.event_log.add_event("Route Reply sent back", PacketType.RREP, path[-1], path[-2])
        
        # Record in PCAP
        self.add_pcap_packet(PacketType.RREP, path[-1], path[-2], len(path)-1, rrep_path)
    
    def send_data_packet(self):
        data_packet = AnimatedPacket(self.packet_counter, PacketType.DATA, self.final_path, base_speed=0.8)
        self.packet_queue.append(data_packet)
        self.packet_counter += 1
        
        if self.event_log:
            self.event_log.add_event("Data transmission started", PacketType.DATA, self.source, self.final_path[1])
        
        # Record in PCAP
        self.add_pcap_packet(PacketType.DATA, self.source, self.final_path[1], 1, self.final_path)
    
    def simulate_route_error(self):
        if not self.final_path or len(self.final_path) < 3:
            if self.event_log:
                self.event_log.add_event("Cannot simulate RERR - no established route")
            return
        
        break_index = random.randint(1, len(self.final_path) - 2)
        from_node = self.final_path[break_index - 1]
        to_node = self.final_path[break_index]
        
        rerr_path = [from_node, to_node]
        rerr_packet = AnimatedPacket(self.packet_counter, PacketType.RERR, rerr_path, base_speed=0.8,
                                   from_node=from_node, to_node=to_node)
        self.packet_queue.append(rerr_packet)
        self.packet_counter += 1
        
        if self.event_log:
            self.event_log.add_event("Simulating Route Error - Link break", PacketType.RERR, from_node, to_node)
        
        # Record in PCAP
        self.add_pcap_packet(PacketType.RERR, from_node, to_node, 1, rerr_path)
    
    def update(self, delta_time):
        if not self.simulation_running:
            return
            
        if self.mobility_enabled:
            for node in self.nodes:
                node.update_position(delta_time)
                node.update_neighbors(self.nodes)
        
        completed_packets = []
        for packet in self.active_packets:
            if packet.update(delta_time, self.animation_speed):
                completed_packets.append(packet)
        
        for packet in completed_packets:
            self.active_packets.remove(packet)
            self.process_packet_completion(packet)
        
        while self.packet_queue and len(self.active_packets) < 5:
            new_packet = self.packet_queue.popleft()
            self.active_packets.append(new_packet)
        
        if not self.active_packets and not self.packet_queue and self.simulation_running:
            if self.final_path:
                self.send_data_packet()
            else:
                self.simulation_complete = True
                self.simulation_running = False
    
    def set_animation_speed(self, speed):
        self.animation_speed = speed

    def draw(self, screen, font):
        for x in range(0, NETWORK_WIDTH, 80):
            pygame.draw.line(screen, GRID_COLOR, (x, 0), (x, HEIGHT), 1)
        for y in range(0, HEIGHT, 80):
            pygame.draw.line(screen, GRID_COLOR, (0, y), (NETWORK_WIDTH, y), 1)
        
        for node in self.nodes:
            for neighbor in node.neighbors:
                pygame.draw.line(screen, (80, 80, 80, 100), (node.x, node.y), 
                               (neighbor.x, neighbor.y), 1)
        
        for path in self.discovered_paths[-50:]:
            for i in range(len(path) - 1):
                node1 = self.nodes[path[i]]
                node2 = self.nodes[path[i + 1]]
                pygame.draw.line(screen, (100, 100, 100, 150), (node1.x, node1.y), 
                               (node2.x, node2.y), 2)
        
        for node in self.nodes:
            is_source = (node.id == self.source)
            is_dest = (node.id == self.destination)
            node.draw(screen, font, False, is_source, is_dest)
        
        if self.final_path:
            for i in range(len(self.final_path) - 1):
                node1 = self.nodes[self.final_path[i]]
                node2 = self.nodes[self.final_path[i + 1]]
                pygame.draw.line(screen, HIGHLIGHT_COLOR, (node1.x, node1.y), 
                               (node2.x, node2.y), 4)
        
        for packet in self.active_packets:
            packet.draw(screen, self.nodes)

def draw_introduction_screen(screen, start_button):
    screen.fill(INTRO_BG)
    
    # Add a subtle background pattern
    for x in range(0, WIDTH, 40):
        for y in range(0, HEIGHT, 40):
            if (x + y) % 80 == 0:
                pygame.draw.circle(screen, (30, 40, 60, 50), (x, y), 1)
    
    title_font = pygame.font.SysFont('Arial', 48, bold=True)
    heading_font = pygame.font.SysFont('Arial', 28, bold=True)
    subheading_font = pygame.font.SysFont('Arial', 22, bold=True)
    text_font = pygame.font.SysFont('Arial', 18)
    bullet_font = pygame.font.SysFont('Arial', 16)
    
    # Title Section
    title = title_font.render("AODV Protocol Simulator", True, (100, 200, 255))
    subtitle = text_font.render("Ad-hoc On-demand Distance Vector Routing Protocol", True, (180, 180, 220))
    screen.blit(title, (WIDTH//2 - title.get_width()//2, 40))
    screen.blit(subtitle, (WIDTH//2 - subtitle.get_width()//2, 100))
    
    # Column dimensions
    col_width = 450
    col_spacing = 30
    left_col = 50
    middle_col = left_col + col_width + col_spacing
    right_col = middle_col + col_width + col_spacing
    
    # Column backgrounds
    col_height = HEIGHT - 200
    for x in [left_col, middle_col, right_col]:
        col_rect = pygame.Rect(x, 150, col_width, col_height)
        pygame.draw.rect(screen, (25, 35, 50, 180), col_rect, border_radius=15)
        pygame.draw.rect(screen, (60, 80, 100), col_rect, 2, border_radius=15)
    
    # Column 1: What is AODV?
    what_title = heading_font.render("What is AODV?", True, (100, 255, 200))
    screen.blit(what_title, (left_col + 20, 170))
    
    aodv_description = [
        "AODV (Ad-hoc On-demand Distance Vector) is a",
        "reactive routing protocol designed for mobile",
        "ad-hoc networks (MANETs). It establishes routes",
        "only when needed, making it efficient for",
        "dynamic network environments."
    ]
    
    for i, line in enumerate(aodv_description):
        text = text_font.render(line, True, TEXT_COLOR)
        screen.blit(text, (left_col + 30, 220 + i * 30))
    
    key_features = subheading_font.render("Key Features:", True, (255, 200, 100))
    screen.blit(key_features, (left_col + 20, 380))
    
    features = [
        "• On-demand route discovery",
        "• Loop-free routing",
        "• Route maintenance",
        "• Scalable for large networks",
        "• Handles mobility efficiently"
    ]
    
    for i, feature in enumerate(features):
        text = bullet_font.render(feature, True, (200, 230, 255))
        screen.blit(text, (left_col + 40, 420 + i * 28))
    
    # Column 2: How AODV Works
    how_title = heading_font.render("How AODV Works", True, (255, 200, 100))
    screen.blit(how_title, (middle_col + 20, 170))
    
    steps = [
        "1. ROUTE DISCOVERY",
        "   • Source broadcasts RREQ (Route Request)",
        "   • Intermediate nodes forward RREQ",
        "   • Destination sends RREP (Route Reply)",
        "",
        "2. ROUTE ESTABLISHMENT", 
        "   • RREP travels back to source",
        "   • Route table entries created",
        "   • Data transmission begins",
        "",
        "3. ROUTE MAINTENANCE",
        "   • Hello messages detect link breaks",
        "   • RERR (Route Error) messages sent",
        "   • New route discovery if needed"
    ]
    
    for i, step in enumerate(steps):
        color = TEXT_COLOR if not step or step[0].isdigit() else (180, 220, 255)
        text = bullet_font.render(step, True, color)
        screen.blit(text, (middle_col + 30, 220 + i * 24))
    
    # Column 3: Packet Types & Simulation
    packet_title = heading_font.render("Packet Types", True, (200, 150, 255))
    screen.blit(packet_title, (right_col + 20, 170))
    
    # Packet type boxes
    packet_types = [
        (RREQ_COLOR, "RREQ", "Route Request", "Broadcast route discovery"),
        (RREP_COLOR, "RREP", "Route Reply", "Unicast route establishment"),
        (DATA_COLOR, "DATA", "Data Packet", "Actual data transmission"),
        (RERR_COLOR, "RERR", "Route Error", "Link break notification")
    ]
    
    for i, (color, abbrev, name, desc) in enumerate(packet_types):
        y_pos = 220 + i * 100
        
        # Packet color indicator
        pygame.draw.rect(screen, color, (right_col + 30, y_pos, 40, 40), border_radius=8)
        pygame.draw.rect(screen, (220, 220, 220), (right_col + 30, y_pos, 40, 40), 2, border_radius=8)
        
        # Packet info
        abbrev_text = subheading_font.render(abbrev, True, TEXT_COLOR)
        name_text = text_font.render(name, True, color)
        desc_text = bullet_font.render(desc, True, (180, 200, 220))
        
        screen.blit(abbrev_text, (right_col + 80, y_pos))
        screen.blit(name_text, (right_col + 80, y_pos + 25))
        screen.blit(desc_text, (right_col + 30, y_pos + 50))
    
    # Start Simulation Button
    start_button.rect.x = right_col + 100
    start_button.rect.y = HEIGHT - 120
    start_button.rect.width = 250
    start_button.rect.height = 60
    
    start_button.draw(screen)
    
    # Footer
    footer = text_font.render("Click 'Start Simulation' to explore AODV in action!", True, (200, 200, 255))
    screen.blit(footer, (WIDTH//2 - footer.get_width()//2, HEIGHT - 40))

def draw_simulation_screen(screen, font, title_font, node_input, set_nodes_button, run_sim_button, 
                 reset_button, new_formation_button, rerr_button, pcap_button, speed_slider, mobility_toggle, simulator):
    panel_rect = pygame.Rect(NETWORK_WIDTH, 0, WIDTH - NETWORK_WIDTH, HEIGHT)
    pygame.draw.rect(screen, UI_COLOR, panel_rect)
    pygame.draw.line(screen, (60, 80, 100), (NETWORK_WIDTH, 0), (NETWORK_WIDTH, HEIGHT), 3)
    
    title = title_font.render("AODV SIMULATOR", True, (255, 255, 200))
    screen.blit(title, (NETWORK_WIDTH + 20, 25))
    
    if simulator.event_log:
        simulator.event_log.draw(screen)
    
    controls_y = 220
    control_title = font.render("CONTROLS", True, (200, 200, 255))
    screen.blit(control_title, (NETWORK_WIDTH + 20, controls_y))
    
    node_text = font.render("Nodes:", True, TEXT_COLOR)
    screen.blit(node_text, (NETWORK_WIDTH + 20, controls_y + 40))
    
    node_input.draw(screen)
    set_nodes_button.draw(screen)
    
    speed_slider.rect.y = controls_y + 90
    speed_slider.draw(screen)
    
    mobility_label = font.render("Mobility:", True, TEXT_COLOR)
    screen.blit(mobility_label, (NETWORK_WIDTH + 20, controls_y + 130))
    mobility_toggle.rect.y = controls_y + 130
    mobility_toggle.draw(screen)
    
    # First row of buttons
    run_sim_button.rect.y = controls_y + 180
    run_sim_button.rect.width = 120
    reset_button.rect.y = controls_y + 180
    reset_button.rect.x = NETWORK_WIDTH + 150
    reset_button.rect.width = 120
    
    # Second row of buttons
    rerr_button.rect.y = controls_y + 230
    rerr_button.rect.width = 120
    new_formation_button.rect.y = controls_y + 230
    new_formation_button.rect.x = NETWORK_WIDTH + 150
    new_formation_button.rect.width = 120
    
    # Third row - PCAP button
    pcap_button.rect.y = controls_y + 280
    pcap_button.rect.width = WIDTH - NETWORK_WIDTH - 40
    pcap_button.rect.x = NETWORK_WIDTH + 20
    
    run_sim_button.draw(screen)
    reset_button.draw(screen)
    rerr_button.draw(screen)
    new_formation_button.draw(screen)
    pcap_button.draw(screen)
    
    status_y = 550
    status_title = font.render("STATUS", True, (200, 200, 255))
    screen.blit(status_title, (NETWORK_WIDTH + 20, status_y))
    
    status_info = [
        f"Total Nodes: {len(simulator.nodes)}",
        f"Source: {simulator.source if simulator.source is not None else 'None'}",
        f"Target: {simulator.destination if simulator.destination is not None else 'None'}",
        f"Active Packets: {len(simulator.active_packets)}",
        f"Queued Packets: {len(simulator.packet_queue)}",
        f"Paths Found: {len(simulator.all_discovered_paths_to_dest)}",
        f"Best Hops: {simulator.best_path_hop_count if simulator.best_path_hop_count != float('inf') else 'N/A'}",
        f"Mobility: {'ON' if simulator.mobility_enabled else 'OFF'}",
        f"PCAP Packets: {len(simulator.pcap_packets)}",
        f"State: {'RUNNING' if simulator.simulation_running else 'DONE' if simulator.simulation_complete else 'READY'}"
    ]
    
    for i, line in enumerate(status_info):
        text = font.render(line, True, TEXT_COLOR)
        screen.blit(text, (NETWORK_WIDTH + 20, status_y + 35 + i * 25))
    
    legend_y = 800
    legend_title = font.render("LEGEND", True, (200, 200, 255))
    screen.blit(legend_title, (NETWORK_WIDTH + 20, legend_y))
    
    legend_items = [
        (RREQ_COLOR, "RREQ - Route Request"),
        (RREP_COLOR, "RREP - Route Reply"), 
        (DATA_COLOR, "DATA - Data Packet"),
        (RERR_COLOR, "RERR - Route Error"),
        (HIGHLIGHT_COLOR, "Final Path"),
        ((100, 100, 100), "Explored Paths")
    ]
    
    for i, (color, text) in enumerate(legend_items):
        pygame.draw.rect(screen, color, (NETWORK_WIDTH + 20, legend_y + 35 + i * 25, 16, 16))
        legend_text = font.render(text, True, TEXT_COLOR)
        screen.blit(legend_text, (NETWORK_WIDTH + 45, legend_y + 35 + i * 25))

def main():
    screen = pygame.display.set_mode((WIDTH, HEIGHT))
    pygame.display.set_caption("AODV Protocol Simulator with PCAP Export")
    clock = pygame.time.Clock()
    
    font = pygame.font.SysFont('Arial', 14)
    title_font = pygame.font.SysFont('Arial', 20, bold=True)
    button_font = pygame.font.SysFont('Arial', 20, bold=True)
    
    # Game state
    current_state = GameState.INTRODUCTION
    
    # Introduction screen elements
    start_button = Button(WIDTH//2 - 100, HEIGHT - 150, 200, 50, "Start Simulation", button_font, 
                         color=(50, 180, 80), hover_color=(70, 220, 100))
    
    # Simulation objects
    simulator = AODVSimulator()
    simulator.event_log = EventLog(NETWORK_WIDTH + 10, 60, WIDTH - NETWORK_WIDTH - 5, 150, font, max_events=20)
    
    # Simulation UI elements
    node_input = InputBox(NETWORK_WIDTH + 80, 260, 60, 28, font, '15')
    set_nodes_button = Button(NETWORK_WIDTH + 150, 260, 80, 28, "Apply", font)
    speed_slider = Slider(NETWORK_WIDTH + 20, 310, WIDTH - NETWORK_WIDTH - 40, 16, 0.3, 2.0, 1.0, font, "Speed")
    mobility_toggle = ToggleButton(NETWORK_WIDTH + 90, 340, 50, 25, "", font)
    run_sim_button = Button(NETWORK_WIDTH + 20, 380, 120, 35, "RUN SIM", font)
    reset_button = Button(NETWORK_WIDTH + 150, 380, 120, 35, "RESET", font)
    rerr_button = Button(NETWORK_WIDTH + 20, 430, 120, 35, "SIM RERR", font)
    new_formation_button = Button(NETWORK_WIDTH + 150, 430, 120, 35, "NEW FORM", font)
    pcap_button = Button(NETWORK_WIDTH + 20, 480, 120, 35, "GENERATE PCAP", font, 
                         color=(180, 100, 50), hover_color=(220, 140, 70))
    
    running = True
    last_time = time.time()
    pcap_generated = False
    
    while running:
        current_time = time.time()
        delta_time = current_time - last_time
        last_time = current_time
        
        delta_time = min(delta_time, 0.033)
        
        mouse_pos = pygame.mouse.get_pos()
        events = pygame.event.get()
        
        for event in events:
            if event.type == pygame.QUIT:
                running = False
            
            # Handle event log scrolling
            if current_state == GameState.SIMULATION:
                if simulator.event_log.handle_event(event, mouse_pos):
                    continue
            
            if current_state == GameState.INTRODUCTION:
                if start_button.is_clicked(mouse_pos, event):
                    current_state = GameState.SIMULATION
            
            elif current_state == GameState.SIMULATION:
                new_text = node_input.handle_event(event)
                if new_text != node_input.text:
                    node_input.text = new_text
                
                speed_slider.handle_event(event)
                simulator.set_animation_speed(speed_slider.value)
                
                if mobility_toggle.is_clicked(mouse_pos, event):
                    simulator.toggle_mobility()
                
                if set_nodes_button.is_clicked(mouse_pos, event):
                    if node_input.text.isdigit():
                        simulator.num_nodes = min(max(3, int(node_input.text)), 99)
                        simulator.setup_nodes()
                        simulator.source = None
                        simulator.destination = None
                        if simulator.event_log:
                            simulator.event_log.add_event(f"Network reset: {simulator.num_nodes} nodes")
                
                if run_sim_button.is_clicked(mouse_pos, event):
                    if simulator.source is not None and simulator.destination is not None:
                        simulator.start_simulation()
                        pcap_generated = False
                
                if reset_button.is_clicked(mouse_pos, event):
                    simulator.reset_simulation()
                    simulator.source = None
                    simulator.destination = None
                    pcap_generated = False
                
                if rerr_button.is_clicked(mouse_pos, event):
                    simulator.simulate_route_error()
                
                if new_formation_button.is_clicked(mouse_pos, event):
                    simulator.setup_nodes()
                    simulator.source = None
                    simulator.destination = None
                    simulator.reset_simulation()
                    pcap_generated = False
                
                if pcap_button.is_clicked(mouse_pos, event):
                    if simulator.pcap_packets:
                        filename = simulator.generate_pcap_file()
                        if filename:
                            if simulator.event_log:
                                simulator.event_log.add_event(f"PCAP file generated: {filename}")
                            pcap_generated = True
                            # Update button text to show success
                            pcap_button.text = "PCAP GENERATED!"
                    else:
                        if simulator.event_log:
                            simulator.event_log.add_event("No packets captured for PCAP generation")
                
                if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
                    if mouse_pos[0] < NETWORK_WIDTH:
                        for node in simulator.nodes:
                            if math.sqrt((node.x - mouse_pos[0])**2 + (node.y - mouse_pos[1])**2) <= NODE_RADIUS:
                                if simulator.source is None:
                                    simulator.source = node.id
                                    if simulator.event_log:
                                        simulator.event_log.add_event(f"Source: Node {node.id}")
                                elif simulator.destination is None and node.id != simulator.source:
                                    simulator.destination = node.id
                                    if simulator.event_log:
                                        simulator.event_log.add_event(f"Target: Node {node.id}")
                                else:
                                    simulator.source = node.id
                                    simulator.destination = None
                                    if simulator.event_log:
                                        simulator.event_log.add_event(f"Source: Node {node.id}")
                                break
        
        # Update hover states
        if current_state == GameState.INTRODUCTION:
            start_button.is_hovered(mouse_pos)
        else:
            set_nodes_button.is_hovered(mouse_pos)
            run_sim_button.is_hovered(mouse_pos)
            reset_button.is_hovered(mouse_pos)
            rerr_button.is_hovered(mouse_pos)
            new_formation_button.is_hovered(mouse_pos)
            pcap_button.is_hovered(mouse_pos)
            mobility_toggle.is_hovered(mouse_pos)
        
        # Update simulation
        if current_state == GameState.SIMULATION:
            simulator.update(delta_time)
            
            # Reset PCAP button text after generation
            if pcap_generated and not pcap_button.hovered:
                pcap_button.text = "GENERATE PCAP"
                pcap_generated = False
        
        # Draw appropriate screen
        screen.fill(BACKGROUND)
        
        if current_state == GameState.INTRODUCTION:
            draw_introduction_screen(screen, start_button)
        else:
            simulator.draw(screen, font)
            draw_simulation_screen(screen, font, title_font, node_input, set_nodes_button, run_sim_button, 
                                 reset_button, new_formation_button, rerr_button, pcap_button, speed_slider, mobility_toggle, simulator)
        
        pygame.display.flip()
        clock.tick(60)
    
    pygame.quit()

if __name__ == "__main__":
    main()