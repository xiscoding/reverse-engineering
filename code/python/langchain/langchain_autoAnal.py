#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr 24 04:33:49 2024

@author: xdoestech
"""
#############################################################################
## LLM

local_llm = 'llama3'
### Index

from langchain.text_splitter import RecursiveCharacterTextSplitter
#from langchain_community.document_loaders import WebBaseLoader
from langchain_community.document_loaders import DirectoryLoader
from langchain_community.document_loaders.text import TextLoader
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import GPT4AllEmbeddings
#############################################################################

analyze_disassembled_flow = """
<|begin_of_text|><|start_header_id|>system<|end_header_id|> 
Based on the provided disassembled binary code, perform the following analysis:
1. Identify the control flow structures present in the code, such as loops (e.g., `jmp`, `loop`), conditional statements (e.g., `je`, `jne`), and function calls (e.g., `call` instructions).
2. Examine the data structures being used, which could include arrays, strings (e.g., sequences of characters), or structures (e.g., structs or records).
3. Develop an understanding of how the program's execution flow works, considering the identified control flow structures and potential data dependencies.
4. Highlight any areas of interest, such as unusual control flow patterns, potential vulnerabilities (e.g., buffer overflows, integer overflows), or code obfuscation techniques.
5. If there is a main function always analyze and include it
6. Ignore the imported or automatically generated functions, like those in the .init, .plt, .plt.got, .plt.sec, __libc_csu_init, and __libc_csu_fini sections, as well as standard library functions like puts, strlen, __stack_chk_fail, printf, strcmp, and __isoc99_scanf
Respond with a dictionary where the keys are function names (e.g., `main`, `obfuscate_password`, `check_password`), and the values are strings describing the function's importance, control flow characteristics, data structures used, and any other relevant observations.
For example:
{{
    "main": "Appears to be the entry point, calls `check_password` function, uses conditional jumps based on the return value",
    "obfuscate_password": "Modifies a string (likely a password) using an XOR operation, loops through string characters",
    "check_password": "Compares a provided string with an obfuscated password, uses string manipulation functions"
}}
<|eot_id|><|start_header_id|>user<|end_header_id|>
Here is the retrieved disassembled binary code: \n\n {disassembled_str} \n
<|eot_id|><|start_header_id|>assistant<|end_header_id|>
"""

analyze_disassembled_detect_obfuscation = """
Based on the provided disassembled binary code, perform the following analysis:
1. Identify the potential purpose of the code, determine memory locations, conditionals, etc that may be important
2. Identify any unusual patterns or unconventional coding practices that deviate from standard programming techniques or conventions. These could include:
   - Convoluted control flow (e.g., unnecessary jumps, redundant instructions)
   - Obfuscated data structures or variable encodings
   - Usage of anti-debugging or anti-virtualization techniques
3. Look for sections of code that seem designed to hinder reverse engineering efforts, such as:
   - Code flattening or control flow obfuscation techniques
   - Encrypted or encoded code sections
   - Anti-disassembly or anti-tampering mechanisms
4. If any obfuscation or anti-analysis techniques are detected, provide an analysis of their purpose and potential impact on the reverse engineering process. This could include:
   - Explaining how the technique works and what it aims to achieve
   - Assessing the difficulty of bypassing or analyzing the obfuscated code
   - Identifying potential vulnerabilities or weaknesses in the obfuscation technique
Respond with a detailed analysis, including specific examples from the code if applicable. If no obfuscation or anti-analysis techniques are detected, explicitly state that the code appears to be unobfuscated based on your analysis.

Example responses:
- "The code does not appear to be obfuscated or employ any anti-analysis techniques based on the provided disassembly."
- "The binary seems to be packed or encrypted, making it difficult to analyze the code directly. Further unpacking or decryption steps may be required."
- "The code appears to use control flow flattening techniques, likely to hinder disassembly and analysis. This obfuscation technique aims to... [provide detailed analysis]"
<|eot_id|><|start_header_id|>user<|end_header_id|>
Here is the retrieved disassembled binary code: \n\n {disassembled_str} \n
<|eot_id|><|start_header_id|>assistant<|end_header_id|>
"""

analyze_decompiled_analysis = """
<|begin_of_text|><|start_header_id|>system<|end_header_id|> You are an assistant with expert c and assembly language knowledge.
You are very knowledgeable in c code and have an understanding of all standard libary functions.
Assume functions, like those in the .init, .plt, .plt.got, .plt.sec, __libc_csu_init, and __libc_csu_fini sections, as well as standard library functions like puts, strlen, __stack_chk_fail, printf, strcmp, and __isoc99_scanf are defined normally and not overridden.
The information below provides further instructions for you to follow and information for you to review/analyze. 

Based on the Question, Context, and Selected Decompiled Code below, perform each analysis step below:
1. Analyze the decompiled code's purpose and functionality, considering the identified function descriptions and context.
2. Explain each function in the decompiled code and determine how it may be used in the main program.
3. Draft an outline for how to use the decompiled code to further understand the program.
4. Identify any additional information needed to answer the program, then explain how to obtain said information.
Respond with your findings from each step you preformed in each analysis step.
 
<|eot_id|><|start_header_id|>user<|end_header_id|>
Question: {question} 
Context: {context} 
Selected Decompiled Code: \n {decompiled_code} \n
Answer: <|eot_id|><|start_header_id|>assistant<|end_header_id|>
"""
#############################################################################
#file / directory path

DECOMPILED_C_PATH = "/home/xdoestech/Desktop/reverse_engineering/code/python/angr/ghidrecomps/bins/yeungrebecca_170091_32959806_crackme-2ccd11f53888bff06925602985688503/decomps"
DISASSEMBLED_FILE_PATH = "/home/xdoestech/Desktop/langchain_ex/disassembled_yeung.txt"

#############################################################################
# FUNCTIONS
### Find Function Files given a list
import os

#find files matching names passed
def find_function_files(function_descriptions, directory):
    """
    Searches a directory for C files that contain functions with specified names.

    Args:
        function_descriptions (dict): A dictionary where keys are function names and values are descriptions.
        directory (str): The directory to search for files.

    Returns:
        dict: A dictionary where keys are function names and values are lists of file paths containing the function.
    """

    function_files = {}
    for function_name, description in function_descriptions.items():
        function_files[function_name] = []
        
        # Search for files starting with the function name
        for filename in os.listdir(directory):
            if filename.endswith(".c") and filename.startswith(function_name):
                file_path = os.path.join(directory, filename)
                function_files[function_name].append(file_path)
    
    return function_files

#copy file to string
def open_and_read_file(file_path):
    """
    Opens a file and returns its contents as a string.

    Args:
        file_path (str): The path to the file.

    Returns:
        str: The contents of the file.
    """

    with open(file_path, "r") as f:
        return f.read()

#copy files to string
def parse_function_files(function_files):
    """
    Parses C files containing functions and returns their contents as a string.

    Args:
        function_files (dict): A dictionary where keys are function names and values are lists of file paths.

    Returns:
        str: A string containing the contents of all function files, separated by function name and new lines.
    """

    function_content = ""
    for function_name, files in function_files.items():
        function_content += f"\n\nFunction: {function_name}\n"
        for file_path in files:
            with open(file_path, "r") as f:
                file_content = f.read()
                function_content += f"{file_content}\n\n"
    
    return function_content

#############################################################################

###LOADERS, DOCUMENTS,

# DirectoryLoader docs: https://python.langchain.com/docs/modules/data_connection/document_loaders/file_directory/
loader = DirectoryLoader(DECOMPILED_C_PATH, glob="**/*.c")
#docs = [WebBaseLoader(url).load() for url in urls]
docs = loader.load()
# docs_list = [item for sublist in docs for item in sublist]

# text_splitter = RecursiveCharacterTextSplitter.from_tiktoken_encoder(
#     chunk_size=250, chunk_overlap=0
# )
# doc_splits = text_splitter.split_documents(docs_list)

# Add to vectorDB
vectorstore = Chroma.from_documents(
    documents=docs,
    collection_name="rag-chroma",
    embedding=GPT4AllEmbeddings(),
)
retriever = vectorstore.as_retriever()

### Load disassembled file
disassembled_file = open_and_read_file(DISASSEMBLED_FILE_PATH)
#############################################################################

## ANALYSIS CHAIN 

from langchain.prompts import PromptTemplate
from langchain_community.chat_models import ChatOllama
from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.output_parsers import StrOutputParser

# LLM
llm = ChatOllama(model=local_llm, format="json", temperature=0)
llm_gpt_4 = ChatOpenAI()
llm_gpt_3 =  ChatOpenAI(model="gpt-3.5-turbo-0125", temperature=0)


##### Disassembled Analysis #####
     ### PROMPT: analyze_disassembled_detect_obfuscation
prompt_analyze_dissassembled = PromptTemplate(
    template = analyze_disassembled_detect_obfuscation,
    input_variables=["disassembled_str"],
)
analyzes_disassembled = prompt_analyze_dissassembled | llm_gpt_4 | StrOutputParser()
disassembled_analysis = analyzes_disassembled.invoke({"disassembled_str": disassembled_file})


##### Function Selection #####
    ### PROMPT: analyze_disassembled_flow
prompt_find_func = PromptTemplate(
    template = analyze_disassembled_flow,
    input_variables=["disassembled_str"],
)
finds_important_functions = prompt_find_func | llm_gpt_3 | JsonOutputParser()
chosen_functions = finds_important_functions.invoke({"disassembled_str": docs})

##### Decompiled (c file) Analysis #####
    ### PROMPT: analyze_decompiled_analysis
prompt_analysis_all = PromptTemplate(
    template = analyze_decompiled_analysis,
    input_variables=["question","context","decompiled_code"],
)
####### GET QUERY, CONTEXT, DECOMPILED CODE
QUERY = "What String would solve this crackme?"
context = disassembled_analysis
c_file_paths= find_function_files(chosen_functions, DECOMPILED_C_PATH)
selected_c_files = parse_function_files(c_file_paths)
analyzes_everything = prompt_analysis_all | llm_gpt_4 | StrOutputParser()
fin_analysis = analyzes_everything.invoke({"question" : QUERY, "context" : context, "decompiled_code": selected_c_files})

###############################################################################   