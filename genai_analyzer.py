"""
GenAI Analyzer Module
Uses Google Gemini 2.5 Flash to provide intelligent analysis of anomaly data.
"""

import os
import pandas as pd
from typing import Dict, Any, List, Optional
import json

try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
    print("⚠️ google-generativeai not installed. Install with: pip install google-generativeai")


class GeminiAnalyzer:
    """Intelligent anomaly analysis using Google Gemini 2.5 Flash"""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Gemini analyzer.
        
        Args:
            api_key: Google API key. If None, will try to get from GEMINI_API_KEY env variable
        """
        if not GENAI_AVAILABLE:
            raise ImportError("google-generativeai package not installed")
        
        # Get API key
        self.api_key = api_key or os.getenv('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError(
                "Gemini API key not provided. Set GEMINI_API_KEY environment variable or pass api_key parameter.\n"
                "Get your API key from: https://makersuite.google.com/app/apikey"
            )
        
        # Configure Gemini
        genai.configure(api_key=self.api_key)
        
        # Initialize model - using gemini-2.0-flash-exp as it's the latest
        # If you specifically want 2.5, use 'gemini-2.5-flash' when available
        self.model = genai.GenerativeModel('gemini-2.5-flash')
        
        # Generation config for consistent output
        self.generation_config = {
            'temperature': 0.7,
            'top_p': 0.95,
            'top_k': 40,
            'max_output_tokens': 3072,  # Increased to reduce cutoffs
            'stop_sequences': ['\n\n---END---'],  # Graceful stopping point
        }
    
    def analyze_anomaly(self, 
                       anomaly_event: pd.Series,
                       timeline_events: pd.DataFrame,
                       all_anomalies: pd.DataFrame,
                       explanation_data: Dict[str, Any]) -> Dict[str, str]:
        """
        Generate comprehensive AI analysis of a specific anomaly.
        
        Args:
            anomaly_event: The specific anomalous event (Series)
            timeline_events: Events in the timeline window around the anomaly
            all_anomalies: All detected anomalies in the dataset
            explanation_data: SHAP explanation data
            
        Returns:
            Dictionary with analysis sections
        """
        # Prepare context for the AI
        context = self._prepare_anomaly_context(
            anomaly_event, 
            timeline_events, 
            all_anomalies,
            explanation_data
        )
        
        # Create prompt
        prompt = self._create_anomaly_analysis_prompt(context)
        
        try:
            # Generate analysis
            response = self.model.generate_content(
                prompt,
                generation_config=self.generation_config
            )
            
            # Parse response
            analysis = self._parse_analysis_response(response.text)
            return analysis
            
        except Exception as e:
            return {
                'error': f"Failed to generate AI analysis: {str(e)}",
                'summary': "AI analysis unavailable",
                'what_happened': "Unable to generate analysis",
                'key_takeaways': "Please check your API key and connection",
                'recommendations': "Retry the analysis or check logs"
            }
    
    def analyze_all_anomalies(self, 
                             all_anomalies: pd.DataFrame,
                             full_dataset: pd.DataFrame) -> Dict[str, str]:
        """
        Generate high-level analysis of all anomalies in the dataset.
        
        Args:
            all_anomalies: DataFrame with all detected anomalies
            full_dataset: Complete dataset
            
        Returns:
            Dictionary with comprehensive analysis
        """
        # Prepare context
        context = self._prepare_global_context(all_anomalies, full_dataset)
        
        # Create prompt
        prompt = self._create_global_analysis_prompt(context)
        
        try:
            # Generate analysis
            response = self.model.generate_content(
                prompt,
                generation_config=self.generation_config
            )
            
            # Parse response
            analysis = self._parse_global_analysis_response(response.text)
            return analysis
            
        except Exception as e:
            return {
                'error': f"Failed to generate global analysis: {str(e)}",
                'overview': "AI analysis unavailable",
                'patterns': "Unable to identify patterns",
                'threat_assessment': "Analysis failed",
                'recommendations': "Please check your API key and connection"
            }
    
    def _prepare_anomaly_context(self,
                                 anomaly_event: pd.Series,
                                 timeline_events: pd.DataFrame,
                                 all_anomalies: pd.DataFrame,
                                 explanation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare structured context for single anomaly analysis"""
        
        # Extract key information
        context = {
            'anomaly': {
                'event_id': str(anomaly_event.get('EventID', 'Unknown')),
                'timestamp': str(anomaly_event.get('TimeCreated', 'Unknown')),
                'computer': str(anomaly_event.get('Computer', 'Unknown')),
                'user': str(anomaly_event.get('User', 'Unknown')),
                'channel': str(anomaly_event.get('Channel', 'Unknown')),
                'risk_score': float(anomaly_event.get('AnomalyScoreNormalized', 0)),
                'provider': str(anomaly_event.get('ProviderName', 'Unknown'))
            },
            'timeline': {
                'events_before': len(timeline_events[timeline_events['SecondsFromAnomaly'] < 0]),
                'events_after': len(timeline_events[timeline_events['SecondsFromAnomaly'] > 0]),
                'total_events': len(timeline_events),
                'time_window': f"{timeline_events['SecondsFromAnomaly'].min():.0f}s to {timeline_events['SecondsFromAnomaly'].max():.0f}s"
            },
            'top_features': explanation_data.get('top_features', [])[:5],
            'global_stats': {
                'total_anomalies': len(all_anomalies),
                'anomaly_rate': f"{(len(all_anomalies) / len(timeline_events) * 100):.2f}%" if len(timeline_events) > 0 else "N/A"
            }
        }
        
        # Add EventID patterns if available
        if 'EventID' in timeline_events.columns:
            event_ids = timeline_events['EventID'].value_counts().head(5).to_dict()
            context['timeline']['common_event_ids'] = {str(k): int(v) for k, v in event_ids.items()}
        
        return context
    
    def _prepare_global_context(self,
                                all_anomalies: pd.DataFrame,
                                full_dataset: pd.DataFrame) -> Dict[str, Any]:
        """Prepare structured context for global analysis"""
        
        context = {
            'dataset_stats': {
                'total_events': len(full_dataset),
                'total_anomalies': len(all_anomalies),
                'anomaly_rate': f"{(len(all_anomalies) / len(full_dataset) * 100):.2f}%"
            },
            'anomalies': []
        }
        
        # Add summary of each anomaly
        for idx, row in all_anomalies.head(20).iterrows():  # Limit to top 20 for token efficiency
            anomaly_summary = {
                'event_id': str(row.get('EventID', 'Unknown')),
                'timestamp': str(row.get('TimeCreated', 'Unknown')),
                'computer': str(row.get('Computer', 'Unknown')),
                'user': str(row.get('User', 'Unknown')),
                'risk_score': float(row.get('AnomalyScoreNormalized', 0)),
                'channel': str(row.get('Channel', 'Unknown'))
            }
            context['anomalies'].append(anomaly_summary)
        
        # Add temporal patterns
        if 'EpochSeconds' in all_anomalies.columns:
            timestamps = pd.to_datetime(all_anomalies['EpochSeconds'], unit='s')
            context['temporal_patterns'] = {
                'time_range': f"{timestamps.min()} to {timestamps.max()}",
                'duration_hours': (timestamps.max() - timestamps.min()).total_seconds() / 3600
            }
        
        # Add EventID distribution
        if 'EventID' in all_anomalies.columns:
            event_id_dist = all_anomalies['EventID'].value_counts().head(10).to_dict()
            context['event_id_distribution'] = {str(k): int(v) for k, v in event_id_dist.items()}
        
        # Add computer distribution
        if 'Computer' in all_anomalies.columns:
            computer_dist = all_anomalies['Computer'].value_counts().head(5).to_dict()
            context['affected_computers'] = {str(k): int(v) for k, v in computer_dist.items()}
        
        return context
    
    def _create_anomaly_analysis_prompt(self, context: Dict[str, Any]) -> str:
        """Create prompt for single anomaly analysis"""
        
        prompt = f"""You are a cybersecurity expert analyzing Windows event logs for potential security threats.

**ANOMALY DETAILS:**
- Event ID: {context['anomaly']['event_id']}
- Timestamp: {context['anomaly']['timestamp']}
- Computer: {context['anomaly']['computer']}
- User: {context['anomaly']['user']}
- Channel: {context['anomaly']['channel']}
- Risk Score: {context['anomaly']['risk_score']:.1%}
- Provider: {context['anomaly']['provider']}

**TIMELINE CONTEXT:**
- Events Before: {context['timeline']['events_before']}
- Events After: {context['timeline']['events_after']}
- Time Window: {context['timeline']['time_window']}
- Common Event IDs in Timeline: {context['timeline'].get('common_event_ids', {})}

**TOP CONTRIBUTING FACTORS:**
{self._format_features(context['top_features'])}

**GLOBAL CONTEXT:**
- Total Anomalies Detected: {context['global_stats']['total_anomalies']}
- Anomaly Rate: {context['global_stats']['anomaly_rate']}

Based on this information, provide a comprehensive security analysis with the following sections.

IMPORTANT: Use EXACTLY these section headers with markdown (##):

## SUMMARY
(2-3 sentences): What is this anomaly and why is it flagged?

## WHAT HAPPENED
(detailed explanation): Explain the sequence of events and what makes this suspicious. Consider the timeline context and the event type.

## KEY TAKEAWAYS
(bullet points): List 3-5 critical insights about this anomaly. Focus on security implications.

## RECOMMENDATIONS
(actionable steps): Provide 3-5 specific actions the security team should take to investigate or remediate this threat.
"""
        return prompt
    
    def _create_global_analysis_prompt(self, context: Dict[str, Any]) -> str:
        """Create prompt for global anomaly analysis"""
        
        prompt = f"""You are a cybersecurity expert analyzing a comprehensive set of anomalies detected in Windows event logs.

**DATASET OVERVIEW:**
- Total Events: {context['dataset_stats']['total_events']}
- Total Anomalies: {context['dataset_stats']['total_anomalies']}
- Anomaly Rate: {context['dataset_stats']['anomaly_rate']}

**TEMPORAL PATTERNS:**
{json.dumps(context.get('temporal_patterns', {}), indent=2)}

**EVENT ID DISTRIBUTION (Top Anomalous Events):**
{json.dumps(context.get('event_id_distribution', {}), indent=2)}

**AFFECTED SYSTEMS:**
{json.dumps(context.get('affected_computers', {}), indent=2)}

**SAMPLE ANOMALIES:**
{json.dumps(context['anomalies'][:10], indent=2)}

Based on this comprehensive view of all detected anomalies, provide a high-level security analysis with the following sections:

1. **OVERVIEW** (3-4 sentences): Summarize the overall threat landscape based on the detected anomalies.

2. **ATTACK PATTERNS** (detailed analysis): Identify potential attack patterns, campaigns, or coordinated activities. Look for:
   - Lateral movement indicators
   - Privilege escalation attempts
   - Data exfiltration signs
   - Persistence mechanisms
   - Reconnaissance activities

3. **THREAT ASSESSMENT** (risk evaluation): Assess the severity and urgency of the threats. Categorize by:
   - Critical threats requiring immediate action
   - High-priority investigations
   - Medium-risk anomalies for monitoring

4. **KEY TAKEAWAYS** (bullet points): List 5-7 critical insights about the overall security posture based on these anomalies.

5. **STRATEGIC RECOMMENDATIONS** (actionable steps): Provide 5-7 strategic recommendations for improving security posture and responding to these threats.

Format your response with clear section headers using markdown (##).
"""
        return prompt
    
    def _format_features(self, features: List[Dict[str, Any]]) -> str:
        """Format feature list for prompt"""
        if not features:
            return "No feature data available"
        
        lines = []
        for feat in features:
            lines.append(
                f"  - {feat['feature']}: {feat['value']:.3f} "
                f"({feat['contribution']} anomaly score by {abs(feat['shap_value']):.3f})"
            )
        return "\n".join(lines)
    
    def _clean_incomplete_sentence(self, text: str) -> str:
        """
        Remove incomplete sentences at the end of text.
        Detects if the last sentence is incomplete and removes it.
        """
        if not text or len(text.strip()) == 0:
            return text
        
        text = text.strip()
        
        # Check if text ends with proper punctuation
        sentence_endings = ['.', '!', '?', ')', ']', '"', "'"]
        
        # If it ends properly, return as is
        if any(text.endswith(ending) for ending in sentence_endings):
            return text
        
        # Find the last complete sentence
        last_period = max(
            text.rfind('.'),
            text.rfind('!'),
            text.rfind('?')
        )
        
        # If we found a sentence ending, cut there
        if last_period > len(text) * 0.5:  # Only if we're keeping at least 50% of content
            return text[:last_period + 1].strip()
        
        # Otherwise return the text with ellipsis to indicate incompleteness
        return text + "..."
    
    def _parse_analysis_response(self, response_text: str) -> Dict[str, str]:
        """Parse AI response into structured sections"""
        
        sections = {
            'summary': '',
            'what_happened': '',
            'key_takeaways': '',
            'recommendations': ''
        }
        
        # Split by markdown headers (## or **SECTION**)
        lines = response_text.split('\n')
        current_section = None
        current_content = []
        
        for line in lines:
            original_line = line
            line_stripped = line.strip()
            
            # Check for section headers (## or **NUMBER. SECTION**)
            is_header = False
            if line_stripped.startswith('##') or (line_stripped.startswith('**') and '**' in line_stripped[2:]):
                is_header = True
                
            if is_header:
                # Save previous section
                if current_section and current_content:
                    sections[current_section] = '\n'.join(current_content).strip()
                    current_content = []
                
                # Determine new section
                header_lower = line_stripped.lower()
                if 'summary' in header_lower or '1.' in header_lower:
                    current_section = 'summary'
                elif 'what happened' in header_lower or '2.' in header_lower:
                    current_section = 'what_happened'
                elif 'key takeaway' in header_lower or 'takeaway' in header_lower or '3.' in header_lower:
                    current_section = 'key_takeaways'
                elif 'recommendation' in header_lower or '4.' in header_lower:
                    current_section = 'recommendations'
                else:
                    current_section = None
            elif current_section is not None:
                # Add content to current section (preserve original formatting)
                if line_stripped:  # Only add non-empty lines
                    current_content.append(original_line.rstrip())
                elif current_content:  # Add empty lines only if we have content
                    current_content.append('')
        
        # Save last section
        if current_section and current_content:
            sections[current_section] = '\n'.join(current_content).strip()
        
        # If parsing failed, put everything in summary
        if not any(sections.values()):
            sections['summary'] = response_text
        
        # Clean incomplete sentences from each section
        for key in sections:
            if sections[key]:
                sections[key] = self._clean_incomplete_sentence(sections[key])
        
        return sections
    
    def _parse_global_analysis_response(self, response_text: str) -> Dict[str, str]:
        """Parse global analysis response into structured sections"""
        
        sections = {
            'overview': '',
            'patterns': '',
            'threat_assessment': '',
            'key_takeaways': '',
            'recommendations': ''
        }
        
        # Split by markdown headers
        lines = response_text.split('\n')
        current_section = None
        current_content = []
        
        for line in lines:
            line = line.strip()
            
            # Check for section headers
            if line.startswith('##'):
                # Save previous section
                if current_section and current_content:
                    sections[current_section] = '\n'.join(current_content).strip()
                
                # Determine new section
                header_lower = line.lower()
                if 'overview' in header_lower:
                    current_section = 'overview'
                elif 'pattern' in header_lower or 'attack' in header_lower:
                    current_section = 'patterns'
                elif 'threat' in header_lower or 'assessment' in header_lower:
                    current_section = 'threat_assessment'
                elif 'key takeaway' in header_lower or 'takeaway' in header_lower:
                    current_section = 'key_takeaways'
                elif 'recommendation' in header_lower or 'strategic' in header_lower:
                    current_section = 'recommendations'
                else:
                    current_section = None
                
                current_content = []
            elif current_section:
                if line:  # Skip empty lines at start
                    current_content.append(line)
        
        # Save last section
        if current_section and current_content:
            sections[current_section] = '\n'.join(current_content).strip()
        
        # If parsing failed, put everything in overview
        if not any(sections.values()):
            sections['overview'] = response_text
        
        # Clean incomplete sentences from each section
        for key in sections:
            if sections[key]:
                sections[key] = self._clean_incomplete_sentence(sections[key])
        
        return sections
