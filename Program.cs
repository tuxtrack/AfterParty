using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Mono.Cecil;

namespace InspectAssembly
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("[-] Usage: AfterParty.exe <path>");
                return;
            }

            try
            {

                foreach (string file in Directory.EnumerateFiles(args[0], "*.exe", SearchOption.AllDirectories))
                {

                    // Make sure that the target is actually an assembly before we get started

                    AssemblyName assemblyName = AssemblyName.GetAssemblyName(file);

                    CheckMethods(file);
                
                }
            }

            catch (System.Exception excpt)
            {
                Console.WriteLine(excpt.Message);
            }
            
             try
            {

                foreach (string file in Directory.EnumerateFiles(args[0], "*.dll", SearchOption.AllDirectories))
                {

                    // Make sure that the target is actually an assembly before we get started

                    AssemblyName assemblyName = AssemblyName.GetAssemblyName(file);

                    CheckMethods(file);
                
                }
            }

            catch (System.Exception excpt)
            {
                Console.WriteLine(excpt.Message);
            }
             
        }
     
    
        static void CheckMethods(string assemblyName)
        {
            // Just in case we run into .NET Remoting
            string[] dnrChannel = { };
            string typeFilterLevel = "ldc.i4.2"; // Default opcode if not set manually
            string filterLevel = "Low";

            // Parse the target assembly and get its types
            AssemblyDefinition assembly = AssemblyDefinition.ReadAssembly(assemblyName);
            IEnumerable<TypeDefinition> allTypes = assembly.MainModule.GetTypes();

            // Pull out all the type with methods that we want to look at
            var validTypes = allTypes.SelectMany(t => t.Methods.Select(m => new { t, m }))
                .Where(x => x.m.HasBody);

            foreach (var method in validTypes)
            {
                // Disassemble the assembly and check for potentially vulnerable functions
                foreach (var instruction in method.m.Body.Instructions)
                {
                    //Console.WriteLine($"{instruction.OpCode} \"{instruction.Operand}\""); //DEBUG
                    
                    // Deserialization checks
                    if (instruction.OpCode.ToString() == "callvirt")
                    {
                        switch (instruction.Operand.ToString())
                        {
                            case string x when x.Contains("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter::Deserialize"):
                                Console.WriteLine(assemblyName.ToUpper());
                                Console.WriteLine("[+] BinaryFormatter::Deserialize() is called in {0}.{1}", method.t.Name, method.m.Name);
                                Console.WriteLine("\tTypeFilterLevel: {0}", filterLevel + '\n');
                                break;
                            case string x when x.Contains("System.Runtime.Serialization.Json.DataContractJsonSerializer::ReadObject"):
                                Console.WriteLine(assemblyName.ToUpper());
                                Console.WriteLine("[+] DataContractJsonSerializer::ReadObject() is called in {0}.{1}", method.t.Name, method.m.Name + '\n');
                                break;
                            case string x when x.Contains("System.Runtime.Serialization.Xml.DataContractSerializer::ReadObject"):
                                Console.WriteLine(assemblyName.ToUpper());
                                Console.WriteLine("[+] DataContractSerializer::ReadObject() is called in {0}.{1}", method.t.Name, method.m.Name + '\n');
                                break;
                            case string x when x.Contains("System.Web.Script.Serialization.JavaScriptSerializer::Deserialize"):
                                Console.WriteLine(assemblyName.ToUpper());
                                Console.WriteLine("[+] JavaScriptSerializer::Deserialize() is called in {0}.{1}", method.t.Name, method.m.Name + '\n');
                                break;
                            case string x when x.Contains("System.Web.UI.LosFormatter::Deserialize"):
                                Console.WriteLine(assemblyName.ToUpper());
                                Console.WriteLine("[+] LosFormatter::Deserialize() is called in {0}.{1}", method.t.Name, method.m.Name + '\n');
                                break;
                            case string x when x.Contains("System.Runtime.Serialization.NetDataContractSerializer::ReadObject"):
                                Console.WriteLine(assemblyName.ToUpper());
                                Console.WriteLine("[+] NetDataContractSerializer::ReadObject() is called in {0}.{1}", method.t.Name, method.m.Name + '\n');
                                break;
                            case string x when x.Contains("System.Runtime.Serialization.NetDataContractSerializer::Deserialize"):
                                Console.WriteLine(assemblyName.ToUpper());
                                Console.WriteLine("[+] NetDataContractSerializer::Deserialize() is called in {0}.{1}", method.t.Name, method.m.Name + '\n');
                                break;
                            case string x when x.Contains("System.Web.UI.ObjectStateFormatter::Deserialize"):
                                Console.WriteLine(assemblyName.ToUpper());
                                Console.WriteLine("[+] ObjectStateFormatter::Deserialize() is called in {0}.{1}", method.t.Name, method.m.Name + '\n');
                                break;
                            case string x when x.Contains("System.Runtime.Serialization.Formatters.Soap.SoapFormatter::Deserialize"):
                                Console.WriteLine(assemblyName.ToUpper());
                                Console.WriteLine("[+] SoapFormatter::Deserialize() is called in {0}.{1}", method.t.Name, method.m.Name + '\n');
                                break;
                            case string x when x.Contains("System.Xml.Serialization.XmlSerializer::Deserialize"):
                                Console.WriteLine(assemblyName.ToUpper());
                                Console.WriteLine("[+] XMLSerializer::Deserialize() is called in {0}.{1}", method.t.Name, method.m.Name + '\n'); 
                                break;

                            // Collect the TypeFilterLevel if it is explicitly set
                            case string x when x.Contains("set_FilterLevel(System.Runtime.Serialization.Formatters.TypeFilterLevel)"):
                                if (typeFilterLevel.EndsWith("3"))
                                {
                                    filterLevel = "Full";
                                }
                                break;
                        }

                    }

                    if (instruction.OpCode.ToString().StartsWith("ldc.i4"))
                    {
                        typeFilterLevel = instruction.OpCode.ToString();
                    }

                    // .NET Remoting checks
                    if (instruction.OpCode.ToString() == "newobj" && instruction.Operand.ToString().Contains("System.Runtime.Remoting.Channels."))
                    {
                        dnrChannel = instruction.Operand.ToString().Split('.');
                    }

                    if (instruction.OpCode.ToString() == "call")
                    {
                        switch (instruction.Operand.ToString())
                        {
                            case string x when x.Contains("System.Runtime.Remoting.Channels.ChannelServices::RegisterChannel"):
                                Console.WriteLine("[+] Assembly registers a .NET Remoting channel ({0}) in {1}.{2}", dnrChannel[5], method.t.Name, method.m.Name + '\n');
                                break;
                        }
                    }
                    
                    // WCF checks
                    if (instruction.OpCode.ToString() == "callvirt")
                    {
                        switch (instruction.Operand.ToString())
                        {
                            case string x when x.Contains("System.ServiceModel.ServiceHost::AddServiceEndpoint"):
                                Console.WriteLine(assemblyName.ToUpper());
                                Console.WriteLine("[+] Assembly appears to be a WCF server" + '\n');
                                break;
                            case string x when x.Contains("System.ServiceModel.ChannelFactory") && x.Contains("CreateChannel"): // System.ServiceModel.ChannelFactory`1<ClassName.ClassName>::CreateChannel()
                                Console.WriteLine(assemblyName.ToUpper());
                                Console.WriteLine("[+] Assembly appears to be a WCF client" + '\n');
                                break;
                        }
                    }
                }
            }
        }
    }

  
}
