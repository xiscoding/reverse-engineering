#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Mar 31 16:23:36 2024

@author: xdoestech
"""
from view_file_info import get_file_info, get_strings, is_elf_file, disassemble,readelf_analysis
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain.prompts import PromptTemplate
from langchain.prompts import PipelinePromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
import os


goal_template = """
We are analyzing a binary file in order to understand its functionality. 
We will be following a static analysis procedure.
"""
analyze_strings = """
Analyze the output of the strings command below. 
Explain which strings may be important or useful for reverse engineering. 
"""
get_ouputmessages_strings = """
List all of the potential ouput messages from the strings output. 
Provide an explanation for why they are potential output messages.
"""
get_other_strings = """
List all other strings that may hold some importance. 
Do not include symbol table, elf sections, or metadata. 
Provide an explanation for why the strings you chose may hold some importance.
"""
strings_template = """
You will analyze the output of the strings command below and explain which strings may be important or useful for reverse engineering.
 List all of the potential ouput messages from the strings output. 
 Provide an explanation for why they are potential output messages.
 List all other strings that may hold some importance. 
 Do not include symbol table, elf sections, or metadata. 
 Provide an explanation for why the strings you chose may hold some importance.
"""
full_strings_template = """
{goal}

{analysis}

{start}
"""
start_template = """
STRING OUTPUT BELOW:
{strings}
"""

def analyze_strings_chain():
    FILENAME = '/home/xdoestech/Desktop/reverse_engineering/myFirst_crackme/fread'
    
    full_prompt = PromptTemplate.from_template(full_strings_template)
    goal_prompt = PromptTemplate.from_template(goal_template)
    analysis_prompt = PromptTemplate.from_template(strings_template)
    start_prompt = PromptTemplate.from_template(start_template)
    input_prompts = [
        ("goal", goal_prompt),
        ("analysis", analysis_prompt),
        ("start", start_prompt),
    ]
    pipeline_prompt = PipelinePromptTemplate(
        final_prompt=full_prompt, pipeline_prompts=input_prompts
    )
    
    
    strings = '\n'.join(get_strings(FILENAME))
    file_info = get_file_info(FILENAME)
    if is_elf_file(file_info):
        print(f"{FILENAME} is an ELF file.")
        file_header, sym_table = readelf_analysis(FILENAME)
        disassembled, hexdump = disassemble(FILENAME)
    else:
        print(f"{FILENAME} is not an ELF file.")
    
    
    output_parser = StrOutputParser()
    model = ChatOpenAI()
    chain = pipeline_prompt | model | output_parser
    
    
    chain.invoke(strings)

def get_loader_directory(input_dir):
    """
    LOAD all files in directory into document loader 
    
    Returns
    -------
    DirectoryLoader (https://python.langchain.com/docs/modules/data_connection/document_loaders/file_directory/)

    """
    from langchain_community.document_loaders import DirectoryLoader

    loader = DirectoryLoader(input_dir, glob="**/*.c", show_progress=True)
    loaded_docs = loader.load()
    return loaded_docs

def get_retriever_vectStore(documents):
    from langchain_community.vectorstores import FAISS
    from langchain_openai import OpenAIEmbeddings
    from langchain_text_splitters import CharacterTextSplitter
    
    #documents = loader.load()
    text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
    texts = text_splitter.split_documents(documents)
    embeddings = OpenAIEmbeddings()
    db = FAISS.from_documents(texts, embeddings)
    retriever = db.as_retriever()
    return retriever


input_dir = "/home/xdoestech/Desktop/reverse_engineering/code/python/angr/ghidrecomps/bins/fread-3bfb44857ba816e47c298f0416ece40a/decomps"
documents = get_loader_directory(input_dir)
retriever = get_retriever_vectStore(documents)

docs = retriever.get_relevant_documents("How many inputs does the program expect?")

analyze_objdump = """
Review the important strings. 
Analyze the disassembled binary below. 
Provide an analysis of the possible functionalities of the binary file. 
"""
