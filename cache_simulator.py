
import tkinter as tk
from tkinter import messagebox
import math
import random
import matplotlib.pyplot as plt

result_text = None

def get_tag_index_offset_bits(cache_size, block_size, memory_size):
    num_offset_bits = int(math.log(block_size, 2))
    print("No of offset bits:", num_offset_bits)
    num_index_bits = int(math.log(cache_size // block_size, 2))
    print("No of index bits:", num_index_bits)
    num_tag_bits = int(math.log(memory_size, 2)) - num_offset_bits - num_index_bits
    print("No of tag bits:", num_tag_bits)
    return num_tag_bits, num_index_bits, num_offset_bits

def address_to_binary(address, num_bits):
    binary_address = bin(address)[2:]
    return binary_address.zfill(num_bits)

class Cache:
    def __init__(self, cache_size, block_size, memory_size, mapping_technique, replacement_policy, write_policy):
        self.cache_size = cache_size
        self.block_size = block_size
        self.memory_size = memory_size
        self.num_tag_bits, self.num_index_bits, self.num_offset_bits = get_tag_index_offset_bits(cache_size, block_size, memory_size)
        self.bytes_per_line = block_size
        self.num_blocks = cache_size // block_size
        self.num_sets = self.num_blocks
        self.cache = {index: {'valid': 0, 'tag': "-", 'data': 0, 'dirty_bit': 0} for index in range(self.num_sets)}
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.mapping_technique = mapping_technique
        self.replacement_policy = replacement_policy
        self.write_policy = write_policy
        self.index_binary = ""

    def access(self, address, operation):
        tag, index = self.get_tag_and_index(address)
        if index in self.cache and self.cache[index]['valid'] and self.cache[index]['tag'] == tag:
            self.hits += 1
            print(f"Cache Hit for {operation} operation at address {address}")
            self.print_cache()
            return f"Cache Hit for {operation} operation at address {address}"
        elif index in self.cache and self.cache[index]['valid'] and self.cache[index]['tag'] != tag:
            self.evictions += 1
            self.misses += 1
            self.cache[index]['valid'] = 1
            self.cache[index]['tag'] = tag

            data = self.fetch_data_from_memory(address)
            self.cache[index]['data'] = data

            # Update dirty bit if needed
            if operation == "Write" and self.write_policy == "Write Back":
                self.cache[index]['dirty_bit'] = True
            print(f"Cache Miss with Eviction for {operation} operation at address {address}")
            self.print_cache()
            return f"Cache Miss with Eviction for {operation} operation at address {address}"
        else:
            # Cache miss
            self.misses += 1
            print(f"Cache Miss for {operation} operation at address {address}")

            # Update cache entry
            self.cache[index]['valid'] = 1
            self.cache[index]['tag'] = tag

            # Fetch data from memory and update cache
            data = self.fetch_data_from_memory(address)
            self.cache[index]['data'] = data

            # Update dirty bit if needed
            if operation == "Write" and self.write_policy == "Write Back":
                self.cache[index]['dirty_bit'] = True

            # Print cache
            self.print_cache()

            # Handle write policies
            if operation == "Write" and self.write_policy == "Write Through":
                print(f"Writing through to memory for address {address}")
            elif operation == "Write" and self.write_policy == "Write Back":
                print(f"Writing back to cache for address {address}")

            return f"Cache Miss for {operation} operation at address {address}"


    def fetch_data_from_memory(self, address):
        return f"BLOCK {address // self.block_size} WORD 0 - 1"

    def get_tag_and_index(self, address):
        instruction_length = self.num_tag_bits + self.num_index_bits + self.num_offset_bits
        binary_address = address_to_binary(address, instruction_length)
        print("Binary Address: ", binary_address)
        
        # Extract offset
        offset = address & ((1 << self.num_offset_bits) - 1)
        print("Offset: ", bin(offset).replace("0b","").zfill(self.num_offset_bits))
        # Shift to extract index and tag
        temp = address >> self.num_offset_bits
        index = temp & ((1 << self.num_index_bits) - 1)
        tag = temp >> self.num_index_bits 
        print("Tag: ", bin(tag).replace("0b","").zfill(self.num_tag_bits))
        print("Index: ", bin(index).replace("0b","").zfill(self.num_index_bits))
        
        return tag, index

    
    def print_cache(self):
        print("\nCache Table:")
        print("Index\tValid\tTag\tData (Hex)\tDirty Bit")
        for index in range(self.num_sets):
            if index in self.cache:
                tag = self.cache[index]['tag']
                data = self.cache[index]['data']
                dirty_bit = self.cache[index]['dirty_bit']
                # Print the information for the current cache entry
                print(f"{index}\t{self.cache[index]['valid']}\t{tag}\t{data}\t{dirty_bit}")
            else:
                # If the index is not in the cache, print as empty
                print(f"{index}\t0\t-\t0\t0")
        print()

def simulate_cache(cache, traces):
    hits = misses = evictions = 0
    results = []
    for trace in traces:
        if not trace.strip():
            continue
        parts = trace.split()
        if len(parts) != 2:
            results.append(f"Invalid memory trace: {trace}")
            continue
        operation, address_str = parts
        if operation not in {"Read", "Write"}:
            results.append(f"Invalid operation: {operation}")
            continue
        try:
            # Attempt to parse address as decimal
            address = int(address_str)
        except ValueError:
            results.append(f"Invalid memory address: {address_str}")
            continue
        result = cache.access(address, operation)
        if result.startswith("Cache Hit"):
            hits += 1
        elif result.startswith("Cache Miss"):
            if "Eviction" in result:
                evictions += 1
            misses += 1
        results.append(result)
    return hits, misses, evictions, results



# Function to run the simulation
def run_simulation(cache_size_entry, block_size_entry, memory_size_entry, mapping_var, replacement_var, write_var, trace_entry):
    global result_text  # Declare result_text as a global variable

    # Retrieve cache parameters from GUI entries
    try:
        cache_size = int(cache_size_entry.get())
        block_size = int(block_size_entry.get())
        memory_size = int(memory_size_entry.get())
        if cache_size <= 0 or block_size <= 0 or memory_size <= 0:
            raise ValueError("Cache size, block size, and memory size must be positive integers.")
        if not cache_size & (cache_size - 1) == 0:  
            raise ValueError("Cache size must be a power of 2.")
        if not block_size & (block_size - 1) == 0:  
            raise ValueError("Block size must be a power of 2.")
    except ValueError as e:
        messagebox.showerror("Error", str(e))
        return

    mapping_technique = mapping_var.get()
    replacement_policy = None if mapping_technique == "Direct" else replacement_var.get()
    write_policy = write_var.get()
    traces = trace_entry.get("1.0", tk.END).strip().split("\n")

    if not traces:
        messagebox.showerror("Error", "Please provide memory traces.")
        return

    # Create cache object and run simulation
    cache = Cache(cache_size, block_size, memory_size, mapping_technique, replacement_policy, write_policy)
    hits, misses, evictions, results = simulate_cache(cache, traces)

    # Calculate hit and miss percentages
    total_accesses = hits + misses
    hit_percentage = (hits / total_accesses) * 100 if total_accesses > 0 else 0
    miss_percentage = (misses / total_accesses) * 100 if total_accesses > 0 else 0

    # Display simulation results in the GUI
    result_text.config(state=tk.NORMAL)
    result_text.delete("1.0", tk.END)
    for result in results:
        result_text.insert(tk.END, result + "\n")
    result_text.insert(tk.END, f"\nHit Percentage: {hit_percentage:.2f}%\n")
    result_text.insert(tk.END, f"Miss Percentage: {miss_percentage:.2f}%\n")
    result_text.config(state=tk.DISABLED)

    visualize_cache_performance(hit_percentage, miss_percentage)

    messagebox.showinfo("Simulation Results",
                        f"Hits: {hits}\nMisses: {misses}\nEvictions: {evictions}\n"
                        f"Hit Percentage: {hit_percentage:.2f}%\n"
                        f"Miss Percentage: {miss_percentage:.2f}%")

# Function to visualize cache performance
def visualize_cache_performance(hit_percentage, miss_percentage):
    labels = ['Hit', 'Miss']
    percentages = [hit_percentage, miss_percentage]

    plt.figure(figsize=(6, 4))
    plt.bar(labels, percentages, color=['green', 'red'])
    plt.title('Cache Performance')
    plt.xlabel('Cache Access')
    plt.ylabel('Percentage')
    plt.ylim(0, 100)

    for i, val in enumerate(percentages):
        plt.text(i, val + 2, f'{val:.2f}%', ha='center', color='black')

    plt.show()

# Function to create the GUI
def create_gui():
    global result_text  # Declare result_text as a global variable

    root = tk.Tk()
    root.title("Cache Simulator")

    cache_frame = tk.Frame(root)
    cache_frame.pack(pady=10)

    # Cache configuration entries
    tk.Label(cache_frame, text="Cache Size (bytes):").grid(row=0, column=0)
    cache_size_entry = tk.Entry(cache_frame)
    cache_size_entry.grid(row=0, column=1)

    tk.Label(cache_frame, text="Block Size (bytes):").grid(row=1, column=0)
    block_size_entry = tk.Entry(cache_frame)
    block_size_entry.grid(row=1, column=1)

    tk.Label(cache_frame, text="Memory Size (bytes):").grid(row=2, column=0)
    memory_size_entry = tk.Entry(cache_frame)
    memory_size_entry.grid(row=2, column=1)

    tk.Label(cache_frame, text="Mapping Technique:").grid(row=3, column=0)
    mapping_var = tk.StringVar(cache_frame, "Direct")
    mapping_menu = tk.OptionMenu(cache_frame, mapping_var, "Direct", "Set Associative", "Associative")
    mapping_menu.grid(row=3, column=1)

    tk.Label(cache_frame, text="Replacement Policy:").grid(row=4, column=0)
    replacement_var = tk.StringVar(cache_frame, "LRU")
    replacement_menu = tk.OptionMenu(cache_frame, replacement_var, "LRU", "FIFO", "Random")
    replacement_menu.grid(row=4, column=1)

    tk.Label(cache_frame, text="Write Policy:").grid(row=5, column=0)
    write_var = tk.StringVar(cache_frame, "Write Back")
    write_menu = tk.OptionMenu(cache_frame, write_var, "Write Back", "Write Through")
    write_menu.grid(row=5, column=1)

    trace_frame = tk.Frame(root)
    trace_frame.pack(pady=10)

    # Text box for memory traces
    tk.Label(trace_frame, text="Memory Traces (operation address):").pack()
    tk.Label(trace_frame, text="Please enter memory accesses in the format: Read/Write address").pack()
    trace_entry = tk.Text(trace_frame, height=10, width=50)
    trace_entry.pack()

    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    # Button to run simulation
    run_button = tk.Button(button_frame, text="Run Simulation", command=lambda: run_simulation(cache_size_entry, block_size_entry, memory_size_entry, mapping_var, replacement_var, write_var, trace_entry))
    run_button.grid(row=0, column=0, padx=10)

    result_frame = tk.Frame(root)
    result_frame.pack()

    # Text box to display simulation results
    tk.Label(result_frame, text="Simulation Results:").pack()
    result_text = tk.Text(result_frame, height=10, width=50, state=tk.DISABLED)
    result_text.pack()

    root.mainloop()

# Main function to create GUI and run the program
def main():
    create_gui()

if __name__ == "__main__":
    main()
