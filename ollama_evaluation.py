#!/usr/bin/env python3
"""
Ollama Model Evaluation Script - Interactive Model Testing and Analysis
Evaluates Ollama models for BloodHound security analysis capabilities
"""

import requests
import json
import time
import os
from typing import Dict, Any, List, Optional


class OllamaModelEvaluator:
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url
        self.headers = {"Content-Type": "application/json"}
        self.available_models = []
        self.results_dir = "evaluation_results"
        
        # Create results directory if it doesn't exist
        self._ensure_results_directory()
    
    def _ensure_results_directory(self):
        """Create evaluation_results directory if it doesn't exist"""
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
            print(f"Created directory: {self.results_dir}")
        elif not os.path.isdir(self.results_dir):
            raise ValueError(f"{self.results_dir} exists but is not a directory")
    
    def _get_results_filename(self, model: str, test_type: str = "complete") -> str:
        """Generate a filename for saving results"""
        timestamp = int(time.time())
        # Clean model name for filename (remove special characters)
        clean_model = model.replace(":", "_").replace("/", "_")
        filename = f"ollama_{test_type}_evaluation_{clean_model}_{timestamp}.json"
        return os.path.join(self.results_dir, filename)
    
    def save_results(self, results: Dict[str, Any], filename: str = None) -> str:
        """Save evaluation results to file"""
        if filename is None:
            model = results.get("model", "unknown")
            filename = self._get_results_filename(model)
        
        try:
            with open(filename, "w") as f:
                json.dump(results, f, indent=2)
            print(f"Results saved to: {filename}")
            return filename
        except Exception as e:
            print(f"ERROR: Failed to save results: {e}")
            return None
    
    def check_connection(self) -> bool:
        """Check if Ollama is running and get available models"""
        print("Checking Ollama connection...")
        
        try:
            # Check version
            response = requests.get(f"{self.base_url}/api/version", timeout=10)
            if response.status_code == 200:
                version_info = response.json()
                print(f"SUCCESS: Ollama running - Version: {version_info.get('version', 'Unknown')}")
            else:
                print(f"ERROR: Version check failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"ERROR: Cannot connect to Ollama: {e}")
            return False
        
        try:
            # Get available models
            response = requests.get(f"{self.base_url}/api/tags", timeout=10)
            if response.status_code == 200:
                models = response.json().get("models", [])
                self.available_models = [model['name'] for model in models]
                print(f"Available models found: {len(self.available_models)}")
                return True
            else:
                print(f"ERROR: Failed to list models: {response.status_code}")
                return False
        except Exception as e:
            print(f"ERROR: Error listing models: {e}")
            return False
    
    def display_models(self) -> str:
        """Display available models and let user select one"""
        if not self.available_models:
            print("No models available")
            return None
        
        print("\nAvailable models:")
        print("-" * 40)
        
        for i, model in enumerate(self.available_models, 1):
            # Extract model name without tag
            model_name = model.split(':')[0]
            model_tag = model.split(':')[1] if ':' in model else 'latest'
            
            # Add some context about common models
            description = ""
            if "deepseek" in model_name.lower():
                description = " (Reasoning model - slow but very capable)"
            elif "llama" in model_name.lower():
                description = " (Fast and reliable)"
            elif "mistral" in model_name.lower():
                description = " (Good balance of speed and capability)"
            elif "codellama" in model_name.lower():
                description = " (Optimized for code and technical content)"
            
            print(f"{i}. {model_name}:{model_tag}{description}")
        
        print("-" * 40)
        
        while True:
            try:
                selection = input(f"Select model (1-{len(self.available_models)}): ").strip()
                
                if selection.lower() in ['q', 'quit', 'exit']:
                    return None
                
                model_index = int(selection) - 1
                if 0 <= model_index < len(self.available_models):
                    selected_model = self.available_models[model_index].split(':')[0]
                    print(f"Selected: {selected_model}")
                    return selected_model
                else:
                    print(f"Please enter a number between 1 and {len(self.available_models)}")
            
            except ValueError:
                print("Please enter a valid number")
            except KeyboardInterrupt:
                print("\nOperation cancelled")
                return None
    
    def get_timeout_for_model(self, model: str, question_type: str = "basic") -> int:
        """Get appropriate timeout based on model and question complexity"""
        base_timeouts = {
            "deepseek": {
                "basic": 60,
                "security": 120,
                "cypher": 150,
                "complex": 180
            },
            "llama": {
                "basic": 30,
                "security": 45,
                "cypher": 60,
                "complex": 90
            },
            "mistral": {
                "basic": 30,
                "security": 45,
                "cypher": 60,
                "complex": 90
            },
            "codellama": {
                "basic": 30,
                "security": 45,
                "cypher": 60,
                "complex": 90
            }
        }
        
        # Determine model family
        model_lower = model.lower()
        if "deepseek" in model_lower:
            model_family = "deepseek"
        elif "llama" in model_lower:
            model_family = "llama"
        elif "mistral" in model_lower:
            model_family = "mistral"
        elif "codellama" in model_lower:
            model_family = "codellama"
        else:
            model_family = "llama"  # Default fallback
        
        return base_timeouts[model_family].get(question_type, base_timeouts[model_family]["basic"])
    
    def send_chat_request(self, model: str, message: str, question_type: str = "basic") -> Optional[Dict]:
        """Send a chat request and return the response"""
        timeout = self.get_timeout_for_model(model, question_type)
        
        # For DeepSeek models, hide the thinking process
        payload = {
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": message
                }
            ],
            "stream": False
        }
        
        # Add think parameter for DeepSeek models to hide thinking process
        if "deepseek" in model.lower():
            payload["think"] = False
            print(f"   NOTE: DeepSeek thinking process will be hidden for cleaner output")
        
        try:
            start_time = time.time()
            
            # Show different messages based on expected wait time
            if timeout >= 120:
                print(f"   Sending to {model}... (reasoning model, may take 60-120s)")
            elif timeout >= 60:
                print(f"   Sending to {model}... (complex question, may take 30-60s)")
            else:
                print(f"   Sending to {model}... (should be quick, <30s)")
            
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=payload,
                headers=self.headers,
                timeout=timeout
            )
            
            end_time = time.time()
            response_time = end_time - start_time
            
            if response.status_code == 200:
                result = response.json()
                message_content = result.get("message", {}).get("content", "")
                
                # For DeepSeek models, also check if thinking was included (should be empty now)
                thinking_content = result.get("message", {}).get("thinking", "")
                if thinking_content and "deepseek" in model.lower():
                    print(f"   WARNING: Thinking process was not hidden properly")
                
                return {
                    "success": True,
                    "content": message_content,
                    "response_time": response_time,
                    "model": model,
                    "thinking_hidden": "deepseek" in model.lower()
                }
            else:
                print(f"   ERROR: Request failed: {response.status_code}")
                print(f"   Response: {response.text[:200]}...")
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}",
                    "response_time": response_time,
                    "model": model
                }
                
        except requests.exceptions.Timeout:
            print(f"   ERROR: Request timed out after {timeout} seconds")
            return {
                "success": False,
                "error": "Timeout",
                "model": model
            }
        except Exception as e:
            print(f"   ERROR: {e}")
            return {
                "success": False,
                "error": str(e),
                "model": model
            }
    
    def test_thinking_behavior(self, model: str) -> Dict[str, Any]:
        """Test if thinking can be controlled for DeepSeek models"""
        if "deepseek" not in model.lower():
            print(f"\nSkipping thinking test - {model} is not a DeepSeek model")
            return {"applicable": False, "reason": "Not a DeepSeek model"}
        
        print(f"\nTesting thinking behavior with {model}")
        
        # Test with thinking enabled
        print("   Testing with thinking enabled...")
        payload_with_thinking = {
            "model": model,
            "messages": [{"role": "user", "content": "What is 2+2? Be very brief."}],
            "stream": False,
            "think": True
        }
        
        # Test with thinking disabled
        print("   Testing with thinking disabled...")
        payload_without_thinking = {
            "model": model,
            "messages": [{"role": "user", "content": "What is 2+2? Be very brief."}],
            "stream": False,
            "think": False
        }
        
        results = {"applicable": True, "with_thinking": None, "without_thinking": None}
        
        try:
            # Test with thinking
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=payload_with_thinking,
                headers=self.headers,
                timeout=90
            )
            
            if response.status_code == 200:
                result = response.json()
                thinking = result.get("message", {}).get("thinking", "")
                content = result.get("message", {}).get("content", "")
                
                results["with_thinking"] = {
                    "has_thinking": len(thinking) > 0,
                    "thinking_length": len(thinking),
                    "content_length": len(content)
                }
                print(f"     With thinking: {len(thinking)} chars thinking, {len(content)} chars content")
            
            # Test without thinking
            response = requests.post(
                f"{self.base_url}/api/chat",
                json=payload_without_thinking,
                headers=self.headers,
                timeout=90
            )
            
            if response.status_code == 200:
                result = response.json()
                thinking = result.get("message", {}).get("thinking", "")
                content = result.get("message", {}).get("content", "")
                
                results["without_thinking"] = {
                    "has_thinking": len(thinking) > 0,
                    "thinking_length": len(thinking),
                    "content_length": len(content)
                }
                print(f"     Without thinking: {len(thinking)} chars thinking, {len(content)} chars content")
        
        except Exception as e:
            print(f"   ERROR: Could not test thinking behavior: {e}")
            results["error"] = str(e)
        
        return results
    
    def test_basic_functionality(self, model: str) -> bool:
        """Test basic chat functionality"""
        print(f"\nTesting basic chat with {model}")
        
        try:
            result = self.send_chat_request(
                model=model,
                message="Say hello and briefly explain what you are in 2 sentences.",
                question_type="basic"
            )
            
            if result and result["success"]:
                print(f"SUCCESS: Basic chat successful!")
                print(f"   Response time: {result['response_time']:.2f}s")
                # Show more of the response for basic functionality test
                content = result['content']
                if len(content) > 200:
                    print(f"   Response: {content[:200]}...")
                    print(f"   Full response length: {len(content)} characters")
                else:
                    print(f"   Response: {content}")
                return True
            else:
                print(f"FAILED: Basic chat failed: {result.get('error', 'Unknown error') if result else 'No response'}")
                return False
        except Exception as e:
            print(f"ERROR: Exception during basic functionality test: {e}")
            return False
    
    def test_security_knowledge(self, model: str) -> Dict[str, Any]:
        """Test security knowledge with simple questions"""
        print(f"\nTesting security knowledge with {model}")
        
        # Initialize default result structure
        results = {
            "total_questions": 3,
            "passed": 0,
            "failed": 0,
            "details": [],
            "error": None
        }
        
        try:
            # Note about DeepSeek timing
            if "deepseek" in model.lower():
                print("   NOTE: DeepSeek is a reasoning model - each question may take 60-120s")
            
            # Simplified security questions
            questions = [
                {
                    "question": "What is BloodHound used for in cybersecurity? One sentence.",
                    "keywords": ["active directory", "attack path", "graph", "security", "penetration"],
                    "name": "BloodHound"
                },
                {
                    "question": "What is Kerberoasting in simple terms? One sentence.",
                    "keywords": ["kerberos", "spn", "service", "ticket", "hash", "crack"],
                    "name": "Kerberoasting"
                },
                {
                    "question": "What does DCSync do? One sentence.",
                    "keywords": ["domain controller", "replication", "credentials", "mimikatz", "sync"],
                    "name": "DCSync"
                }
            ]
            
            for i, q in enumerate(questions, 1):
                print(f"\n   Question {i}: {q['question']}")
                
                try:
                    result = self.send_chat_request(
                        model=model,
                        message=q["question"],
                        question_type="security"
                    )
                    
                    if result and result["success"]:
                        # Check for keywords in response
                        response_lower = result["content"].lower()
                        keyword_matches = sum(1 for keyword in q["keywords"] if keyword in response_lower)
                        
                        if keyword_matches >= 2:  # At least 2 keywords should match
                            print(f"   SUCCESS: Good answer for {q['name']} ({keyword_matches}/{len(q['keywords'])} keywords)")
                            results["passed"] += 1
                            status = "PASS"
                        else:
                            print(f"   WEAK: Weak answer for {q['name']} ({keyword_matches}/{len(q['keywords'])} keywords)")
                            results["failed"] += 1
                            status = "WEAK"
                        
                        results["details"].append({
                            "question": q["name"],
                            "status": status,
                            "response_time": result["response_time"],
                            "keywords_found": keyword_matches,
                            "total_keywords": len(q["keywords"]),
                            "response_preview": result["content"][:100]
                        })
                    else:
                        print(f"   FAILED: Failed to get answer for {q['name']}")
                        results["failed"] += 1
                        results["details"].append({
                            "question": q["name"],
                            "status": "FAIL",
                            "error": result.get("error", "Unknown") if result else "No response"
                        })
                        
                except Exception as e:
                    print(f"   ERROR: Exception during question {i}: {e}")
                    results["failed"] += 1
                    results["details"].append({
                        "question": q["name"],
                        "status": "ERROR",
                        "error": str(e)
                    })
            
            success_rate = (results["passed"] / results["total_questions"]) * 100
            print(f"\n   SUMMARY: Security Knowledge: {results['passed']}/{results['total_questions']} passed ({success_rate:.1f}%)")
            
        except Exception as e:
            print(f"   CRITICAL ERROR: Security knowledge test failed: {e}")
            results["error"] = str(e)
            results["failed"] = results["total_questions"]
        
        return results
    
    def test_cypher_understanding(self, model: str) -> bool:
        """Test understanding of Cypher queries"""
        print(f"\nTesting Cypher understanding with {model}")
        
        try:
            # Note about DeepSeek timing for complex questions
            if "deepseek" in model.lower():
                print("   NOTE: This is a complex question - DeepSeek may take 90-150s to reason through it")
            
            cypher_question = """
            Look at this Cypher query and explain what it finds in one sentence:
            
            MATCH (u:User {hasspn: true, enabled: true}) WHERE NOT u.name ENDS WITH '$' RETURN u.name
            """
            
            result = self.send_chat_request(
                model=model,
                message=cypher_question,
                question_type="cypher"
            )
            
            if result and result["success"]:
                response_lower = result["content"].lower()
                
                # Check for key concepts
                key_concepts = [
                    "kerberoast", "service principal", "spn", "enabled", "users", "service", "accounts"
                ]
                
                concept_matches = sum(1 for concept in key_concepts if concept in response_lower)
                
                print(f"   Response time: {result['response_time']:.2f}s")
                print(f"   Key concepts found: {concept_matches}/{len(key_concepts)}")
                
                if concept_matches >= 3:
                    print(f"   SUCCESS: Good understanding of Cypher and security context")
                    return True
                else:
                    print(f"   WEAK: Limited understanding of security implications")
                    print(f"   Response: {result['content'][:200]}...")
                    return False
            else:
                print(f"   FAILED: Failed to get response: {result.get('error', 'Unknown') if result else 'No response'}")
                return False
        except Exception as e:
            print(f"   ERROR: Exception during Cypher understanding test: {e}")
            return False
    
    def benchmark_model(self, model: str) -> Dict[str, float]:
        """Simple performance benchmark"""
        print(f"\nPerformance benchmark for {model}")
        
        # Initialize default results
        results = {"Simple": -1, "Technical": -1, "Security": -1}
        
        try:
            # Show expected times for DeepSeek
            if "deepseek" in model.lower():
                print("   NOTE: DeepSeek timing expectations:")
                print("     - Simple questions: 30-60s")
                print("     - Technical questions: 60-90s") 
                print("     - Security questions: 90-120s")
            
            test_cases = [
                ("Simple", "What is 2+2?", "basic"),
                ("Technical", "What is Active Directory?", "security"),
                ("Security", "What is privilege escalation?", "security")
            ]
            
            for test_type, question, complexity in test_cases:
                print(f"   Testing {test_type} query...")
                
                try:
                    result = self.send_chat_request(
                        model=model,
                        message=question,
                        question_type=complexity
                    )
                    
                    if result and result["success"]:
                        results[test_type] = result["response_time"]
                        print(f"     SUCCESS: {test_type}: {result['response_time']:.2f}s")
                    else:
                        print(f"     FAILED: {test_type}: Failed")
                        results[test_type] = -1
                except Exception as e:
                    print(f"     ERROR: {test_type}: Exception - {e}")
                    results[test_type] = -1
        
        except Exception as e:
            print(f"   CRITICAL ERROR: Benchmark test failed: {e}")
            # Return default failed results
            for key in results:
                results[key] = -1
        
        return results
    
    def run_complete_evaluation(self, model: str) -> Dict[str, Any]:
        """Run all evaluations on the specified model"""
        print("Starting Complete Ollama Model Evaluation")
        print("=" * 50)
        
        print(f"\nEvaluating model: {model}")
        
        # Run tests
        results = {
            "model": model,
            "available_models": self.available_models,
            "evaluation_timestamp": int(time.time()),
            "evaluation_type": "complete_model_evaluation",
            "tests": {}
        }
        
        # Test thinking behavior for DeepSeek models
        results["tests"]["thinking_behavior"] = self.test_thinking_behavior(model)
        
        # Basic functionality test
        results["tests"]["basic_chat"] = self.test_basic_functionality(model)
        
        # Security knowledge test
        results["tests"]["security_knowledge"] = self.test_security_knowledge(model)
        
        # Cypher understanding test
        results["tests"]["cypher_understanding"] = self.test_cypher_understanding(model)
        
        # Performance benchmark
        results["tests"]["performance"] = self.benchmark_model(model)
        
        # Overall assessment - with safe handling of None results
        basic_pass = results["tests"]["basic_chat"] if results["tests"]["basic_chat"] is not None else False
        
        security_result = results["tests"]["security_knowledge"]
        if security_result is not None and isinstance(security_result, dict):
            security_pass = security_result.get("passed", 0) >= 2
        else:
            security_pass = False
            
        cypher_pass = results["tests"]["cypher_understanding"] if results["tests"]["cypher_understanding"] is not None else False
        
        results["overall_assessment"] = {
            "basic_functionality": "PASS" if basic_pass else "FAIL",
            "security_knowledge": "PASS" if security_pass else "FAIL",
            "cypher_understanding": "PASS" if cypher_pass else "FAIL",
            "recommended_for_production": all([basic_pass, security_pass, cypher_pass])
        }
        
        # Print summary
        self.print_summary(results)
        
        # Save results automatically
        filename = self.save_results(results)
        
        return results
    
    def print_summary(self, results: Dict[str, Any]):
        """Print evaluation summary"""
        print("\n" + "=" * 50)
        print("EVALUATION SUMMARY")
        print("=" * 50)
        
        assessment = results["overall_assessment"]
        model = results["model"]
        
        status = "READY FOR PRODUCTION" if assessment["recommended_for_production"] else "NEEDS IMPROVEMENT"
        print(f"Overall Status: {status}")
        print(f"Model: {model}")
        print(f"Basic Chat: {assessment['basic_functionality']}")
        print(f"Security Knowledge: {assessment['security_knowledge']}")
        print(f"Cypher Understanding: {assessment['cypher_understanding']}")
        
        # Performance summary
        if "performance" in results["tests"]:
            print(f"\nPerformance Summary:")
            for test_type, time_taken in results["tests"]["performance"].items():
                if time_taken > 0:
                    print(f"   {test_type}: {time_taken:.2f}s")
        
        # Recommendations
        print(f"\nRecommendations:")
        if assessment["recommended_for_production"]:
            print(f"   - {model} is ready for BloodHound MCP integration")
            print(f"   - Proceed to Phase 3 of your dev plan")
        else:
            print(f"   - Consider using a different model or adjusting prompts")
            print(f"   - Evaluate with different models to find better performance")
        
        # File location info
        print(f"\nResults Location:")
        print(f"   - Detailed results saved in: {self.results_dir}/")
        print(f"   - Use these results for model selection decisions")
    
    def compare_models(self, models: List[str]) -> Dict[str, Any]:
        """Compare multiple models side by side"""
        print(f"\nComparing models: {', '.join(models)}")
        print("=" * 60)
        
        results = {}
        
        for model in models:
            print(f"\n{'='*20} Testing {model} {'='*20}")
            results[model] = self.run_complete_evaluation(model)
        
        # Create comparison summary
        comparison_results = {
            "comparison_type": "model_comparison",
            "models_tested": models,
            "individual_results": results,
            "timestamp": int(time.time()),
            "summary": self._generate_comparison_summary(results)
        }
        
        # Print comparison summary
        print("\n" + "=" * 60)
        print("MODEL COMPARISON SUMMARY")
        print("=" * 60)
        
        # Performance comparison
        print("\nResponse Time Comparison:")
        print(f"{'Model':<15} {'Basic':<8} {'Security':<10} {'Cypher':<10} {'Overall':<10}")
        print("-" * 60)
        
        for model, result in results.items():
            if "tests" in result and "performance" in result["tests"]:
                perf = result["tests"]["performance"]
                basic = f"{perf.get('Simple', -1):.1f}s" if perf.get('Simple', -1) > 0 else "FAIL"
                security = f"{perf.get('Security', -1):.1f}s" if perf.get('Security', -1) > 0 else "FAIL"
                cypher_time = "N/A"  # We don't benchmark cypher separately
                
                # Calculate average
                valid_times = [t for t in perf.values() if t > 0]
                avg_time = sum(valid_times) / len(valid_times) if valid_times else 0
                overall = f"{avg_time:.1f}s" if avg_time > 0 else "FAIL"
                
                print(f"{model:<15} {basic:<8} {security:<10} {cypher_time:<10} {overall:<10}")
        
        # Quality comparison
        print("\nQuality Comparison:")
        print(f"{'Model':<15} {'Basic':<8} {'Security':<10} {'Cypher':<10} {'Ready?':<10}")
        print("-" * 60)
        
        for model, result in results.items():
            if "overall_assessment" in result:
                assess = result["overall_assessment"]
                basic = assess.get("basic_functionality", "FAIL")
                security = assess.get("security_knowledge", "FAIL")
                cypher = assess.get("cypher_understanding", "FAIL")
                ready = "YES" if assess.get("recommended_for_production", False) else "NO"
                
                print(f"{model:<15} {basic:<8} {security:<10} {cypher:<10} {ready:<10}")
        
        # Recommendations
        print("\nRecommendations:")
        fast_models = []
        capable_models = []
        
        for model, result in results.items():
            if "tests" in result and "performance" in result["tests"]:
                perf = result["tests"]["performance"]
                valid_times = [t for t in perf.values() if t > 0]
                avg_time = sum(valid_times) / len(valid_times) if valid_times else 999
                
                if avg_time < 30:
                    fast_models.append(model)
                
                if "overall_assessment" in result and result["overall_assessment"].get("recommended_for_production", False):
                    capable_models.append(model)
        
        if fast_models:
            print(f"   - Fastest models: {', '.join(fast_models)}")
        if capable_models:
            print(f"   - Most capable models: {', '.join(capable_models)}")
        
        # Best of both worlds
        fast_and_capable = set(fast_models) & set(capable_models)
        if fast_and_capable:
            print(f"   - Best overall: {', '.join(fast_and_capable)}")
        
        # Save comparison results
        filename = self._get_results_filename("comparison", "model_comparison")
        self.save_results(comparison_results, filename)
        
        return comparison_results
    
    def _generate_comparison_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary of the comparison results"""
        summary = {
            "fastest_model": None,
            "most_capable_model": None,
            "best_overall": None,
            "performance_rankings": [],
            "capability_rankings": []
        }
        
        # Find fastest model
        fastest_time = float('inf')
        for model, result in results.items():
            if "tests" in result and "performance" in result["tests"]:
                perf = result["tests"]["performance"]
                valid_times = [t for t in perf.values() if t > 0]
                if valid_times:
                    avg_time = sum(valid_times) / len(valid_times)
                    if avg_time < fastest_time:
                        fastest_time = avg_time
                        summary["fastest_model"] = model
        
        # Find most capable model (highest test pass rate)
        best_score = 0
        for model, result in results.items():
            if "overall_assessment" in result:
                assess = result["overall_assessment"]
                score = sum([
                    assess.get("basic_functionality") == "PASS",
                    assess.get("security_knowledge") == "PASS", 
                    assess.get("cypher_understanding") == "PASS"
                ])
                if score > best_score:
                    best_score = score
                    summary["most_capable_model"] = model
        
        return summary


def main():
    """Main evaluation execution"""
    evaluator = OllamaModelEvaluator()
    
    print("BloodHound Ollama Model Evaluation")
    print("This will evaluate your Ollama models for BloodHound analysis")
    print()
    
    # Check connection and get models
    if not evaluator.check_connection():
        print("Cannot connect to Ollama. Make sure it's running.")
        return
    
    # Let user select model
    selected_model = evaluator.display_models()
    if not selected_model:
        print("No model selected. Exiting.")
        return
    
    # Run evaluation
    print(f"\nRunning evaluation with {selected_model}...")
    results = evaluator.run_complete_evaluation(selected_model)
    
    print(f"\nEvaluation complete! Results saved in: {evaluator.results_dir}/")
    
    # Ask if user wants to evaluate another model
    print("\nWould you like to evaluate another model? (y/n): ", end="")
    try:
        response = input().strip().lower()
        if response in ['y', 'yes']:
            main()  # Recursive call to evaluate another model
    except KeyboardInterrupt:
        print("\nGoodbye!")
    
    return results


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        
        if arg == "--compare":
            # Compare available models
            evaluator = OllamaModelEvaluator()
            if evaluator.check_connection():
                models_to_compare = []
                if "llama3.2:latest" in evaluator.available_models:
                    models_to_compare.append("llama3.2")
                if "deepseek-r1:latest" in evaluator.available_models:
                    models_to_compare.append("deepseek-r1")
                
                if len(models_to_compare) >= 2:
                    results = evaluator.compare_models(models_to_compare)
                else:
                    print("Need at least 2 models to compare")
        else:
            # Evaluate specific model
            evaluator = OllamaModelEvaluator()
            if evaluator.check_connection():
                results = evaluator.run_complete_evaluation(arg)
    else:
        results = main()