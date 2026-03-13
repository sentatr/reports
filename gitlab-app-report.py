import requests
import csv
from collections import defaultdict
import json
from datetime import datetime

class GitLabTopicAccessReport:
def **init**(self, gitlab_url, private_token):
“””
Initialize GitLab API client

```
    Args:
        gitlab_url: GitLab instance URL (e.g., 'https://gitlab.com')
        private_token: GitLab personal access token
    """
    self.gitlab_url = gitlab_url.rstrip('/')
    self.headers = {'PRIVATE-TOKEN': private_token}
    self.api_base = f'{self.gitlab_url}/api/v4'
    self.group_cache = {}

def get_group_details(self, group_id):
    """Fetch group details and cache them"""
    if group_id in self.group_cache:
        return self.group_cache[group_id]
    
    url = f'{self.api_base}/groups/{group_id}'
    response = requests.get(url, headers=self.headers)
    
    if response.status_code == 200:
        group_data = response.json()
        self.group_cache[group_id] = {
            'id': group_data['id'],
            'name': group_data['name'],
            'full_name': group_data['full_name'],
            'full_path': group_data['full_path'],
            'description': group_data.get('description', ''),
            'web_url': group_data['web_url']
        }
        return self.group_cache[group_id]
    else:
        return {
            'id': group_id,
            'name': 'Unknown',
            'full_name': 'Unknown',
            'full_path': 'Unknown',
            'description': '',
            'web_url': ''
        }

def get_all_projects(self):
    """Fetch all projects from GitLab with group information"""
    projects = []
    page = 1
    per_page = 100
    
    print("Fetching all projects...")
    while True:
        url = f'{self.api_base}/projects'
        params = {
            'page': page, 
            'per_page': per_page, 
            'membership': True,
            'with_shared': True  # Include shared projects
        }
        response = requests.get(url, headers=self.headers, params=params)
        
        if response.status_code != 200:
            print(f"Error fetching projects: {response.status_code} - {response.text}")
            break
        
        data = response.json()
        if not data:
            break
            
        projects.extend(data)
        print(f"  Fetched page {page} ({len(data)} projects)")
        page += 1
    
    print(f"Total projects found: {len(projects)}\n")
    return projects

def get_project_members(self, project_id):
    """Fetch all members of a specific project including inherited members"""
    members = []
    page = 1
    per_page = 100
    
    while True:
        url = f'{self.api_base}/projects/{project_id}/members/all'
        params = {'page': page, 'per_page': per_page}
        response = requests.get(url, headers=self.headers, params=params)
        
        if response.status_code != 200:
            print(f"  Warning: Error fetching members for project {project_id}: {response.status_code}")
            break
        
        data = response.json()
        if not data:
            break
            
        members.extend(data)
        page += 1
    
    return members

def get_project_topics(self, project):
    """Extract topics/tags from project"""
    topics = project.get('topics', []) or project.get('tag_list', [])
    return topics if topics else []

def generate_consolidated_report(self, output_csv='topic_access_report.csv', 
                                output_json='topic_access_report.json'):
    """Generate consolidated report of users with access to Topic IDs"""
    
    projects = self.get_all_projects()
    
    # Structure: {topic_id: {user_email: user_details}}
    topic_user_mapping = defaultdict(lambda: defaultdict(lambda: {
        'username': '',
        'name': '',
        'email': '',
        'access_levels': set(),
        'projects': []
    }))
    
    # Track statistics
    stats = {
        'total_projects': len(projects),
        'projects_with_topics': 0,
        'projects_without_topics': 0,
        'unique_topics': set(),
        'total_users': set(),
        'unique_groups': set()
    }
    
    access_level_map = {
        10: 'Guest',
        20: 'Reporter',
        30: 'Developer',
        40: 'Maintainer',
        50: 'Owner'
    }
    
    print("Processing projects and members...")
    for idx, project in enumerate(projects, 1):
        project_id = project['id']
        project_name = project['name']
        project_path = project['path_with_namespace']
        project_web_url = project['web_url']
        project_description = project.get('description', '')
        
        # Get group information
        namespace = project.get('namespace', {})
        group_info = None
        
        if namespace.get('kind') == 'group':
            group_id = namespace.get('id')
            stats['unique_groups'].add(group_id)
            group_info = self.get_group_details(group_id)
        
        topics = self.get_project_topics(project)
        
        if not topics:
            stats['projects_without_topics'] += 1
            continue
        
        stats['projects_with_topics'] += 1
        stats['unique_topics'].update(topics)
        
        print(f"[{idx}/{len(projects)}] Processing: {project_name}")
        print(f"  Group: {group_info['full_name'] if group_info else 'Personal/No Group'}")
        print(f"  Topics: {', '.join(topics)}")
        
        # Get project members
        members = self.get_project_members(project_id)
        print(f"  Members: {len(members)}")
        
        # Map each topic to all members
        for topic_id in topics:
            for member in members:
                email = member.get('email', f"{member['username']}@no-email.com")
                username = member['username']
                name = member['name']
                access_level = access_level_map.get(member['access_level'], 'Unknown')
                
                stats['total_users'].add(email)
                
                # Store user information
                topic_user_mapping[topic_id][email]['username'] = username
                topic_user_mapping[topic_id][email]['name'] = name
                topic_user_mapping[topic_id][email]['email'] = email
                topic_user_mapping[topic_id][email]['access_levels'].add(access_level)
                topic_user_mapping[topic_id][email]['projects'].append({
                    'project_id': project_id,
                    'project_name': project_name,
                    'project_path': project_path,
                    'project_description': project_description,
                    'project_web_url': project_web_url,
                    'group_id': group_info['id'] if group_info else None,
                    'group_name': group_info['name'] if group_info else 'Personal/No Group',
                    'group_full_name': group_info['full_name'] if group_info else 'Personal/No Group',
                    'group_full_path': group_info['full_path'] if group_info else '',
                    'group_web_url': group_info['web_url'] if group_info else '',
                    'access_level': access_level
                })
    
    # Generate CSV Report
    print(f"\n{'='*60}")
    print("Generating CSV report...")
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'Topic ID', 
            'Username', 
            'Name', 
            'Email', 
            'Access Levels', 
            'Project Count',
            'Group Name',
            'Group Full Path',
            'Project Name',
            'Project Path',
            'Project Access Level',
            'Project URL',
            'Group URL'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for topic_id in sorted(topic_user_mapping.keys()):
            for email in sorted(topic_user_mapping[topic_id].keys()):
                user_data = topic_user_mapping[topic_id][email]
                
                # Write one row per project for better visibility
                for project in user_data['projects']:
                    writer.writerow({
                        'Topic ID': topic_id,
                        'Username': user_data['username'],
                        'Name': user_data['name'],
                        'Email': user_data['email'],
                        'Access Levels': ', '.join(sorted(user_data['access_levels'])),
                        'Project Count': len(user_data['projects']),
                        'Group Name': project['group_name'],
                        'Group Full Path': project['group_full_path'],
                        'Project Name': project['project_name'],
                        'Project Path': project['project_path'],
                        'Project Access Level': project['access_level'],
                        'Project URL': project['project_web_url'],
                        'Group URL': project['group_web_url']
                    })
    
    print(f"✓ CSV report generated: {output_csv}")
    
    # Generate Summary CSV (one row per user per topic)
    summary_csv = 'topic_access_summary.csv'
    print("Generating summary CSV report...")
    with open(summary_csv, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'Topic ID', 
            'Username', 
            'Name', 
            'Email', 
            'Access Levels', 
            'Project Count',
            'Projects (Group/Project - Access)'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for topic_id in sorted(topic_user_mapping.keys()):
            for email in sorted(topic_user_mapping[topic_id].keys()):
                user_data = topic_user_mapping[topic_id][email]
                
                # Format projects list with group info
                projects_detail = ' | '.join([
                    f"{p['group_name']}/{p['project_name']} - {p['access_level']}" 
                    for p in user_data['projects']
                ])
                
                writer.writerow({
                    'Topic ID': topic_id,
                    'Username': user_data['username'],
                    'Name': user_data['name'],
                    'Email': user_data['email'],
                    'Access Levels': ', '.join(sorted(user_data['access_levels'])),
                    'Project Count': len(user_data['projects']),
                    'Projects (Group/Project - Access)': projects_detail
                })
    
    print(f"✓ Summary CSV report generated: {summary_csv}")
    
    # Generate JSON Report
    print("Generating JSON report...")
    json_output = {
        'generated_at': datetime.now().isoformat(),
        'statistics': {
            'total_projects': stats['total_projects'],
            'projects_with_topics': stats['projects_with_topics'],
            'projects_without_topics': stats['projects_without_topics'],
            'unique_topics_count': len(stats['unique_topics']),
            'total_unique_users': len(stats['total_users']),
            'unique_groups_count': len(stats['unique_groups'])
        },
        'topics': {}
    }
    
    for topic_id, users in topic_user_mapping.items():
        json_output['topics'][topic_id] = {
            'user_count': len(users),
            'users': {}
        }
        
        for email, data in users.items():
            json_output['topics'][topic_id]['users'][email] = {
                'username': data['username'],
                'name': data['name'],
                'email': data['email'],
                'access_levels': sorted(list(data['access_levels'])),
                'project_count': len(data['projects']),
                'projects': data['projects']
            }
    
    with open(output_json, 'w', encoding='utf-8') as f:
        json.dump(json_output, f, indent=2, ensure_ascii=False)
    
    print(f"✓ JSON report generated: {output_json}")
    
    # Generate Summary Report
    summary_file = 'topic_access_statistics.txt'
    print(f"Generating statistics report...")
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write("GITLAB TOPIC ACCESS REPORT - STATISTICS\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*60 + "\n\n")
        
        f.write("OVERALL STATISTICS:\n")
        f.write(f"  Total Projects: {stats['total_projects']}\n")
        f.write(f"  Projects with Topics: {stats['projects_with_topics']}\n")
        f.write(f"  Projects without Topics: {stats['projects_without_topics']}\n")
        f.write(f"  Unique Topics: {len(stats['unique_topics'])}\n")
        f.write(f"  Unique Groups: {len(stats['unique_groups'])}\n")
        f.write(f"  Total Unique Users: {len(stats['total_users'])}\n\n")
        
        f.write("TOPIC BREAKDOWN:\n")
        f.write("-" * 60 + "\n")
        
        for topic_id in sorted(topic_user_mapping.keys()):
            user_count = len(topic_user_mapping[topic_id])
            project_count = len(set(
                p['project_id'] 
                for user_data in topic_user_mapping[topic_id].values() 
                for p in user_data['projects']
            ))
            
            # Get unique groups for this topic
            groups_for_topic = set(
                p['group_full_name']
                for user_data in topic_user_mapping[topic_id].values()
                for p in user_data['projects']
                if p['group_full_name']
            )
            
            f.write(f"\nTopic: {topic_id}\n")
            f.write(f"  Users with access: {user_count}\n")
            f.write(f"  Associated projects: {project_count}\n")
            f.write(f"  Associated groups: {len(groups_for_topic)}\n")
            f.write(f"  Groups: {', '.join(sorted(groups_for_topic))}\n")
    
    print(f"✓ Statistics report generated: {summary_file}")
    
    # Print summary to console
    print(f"\n{'='*60}")
    print("SUMMARY:")
    print(f"  Total Projects: {stats['total_projects']}")
    print(f"  Projects with Topics: {stats['projects_with_topics']}")
    print(f"  Unique Topics: {len(stats['unique_topics'])}")
    print(f"  Unique Groups: {len(stats['unique_groups'])}")
    print(f"  Total Unique Users: {len(stats['total_users'])}")
    print(f"\nTopics found: {', '.join(sorted(stats['unique_topics']))}")
    print(f"{'='*60}\n")
    
    return topic_user_mapping
```

# Usage Example

if **name** == “**main**”:
# Configuration
GITLAB_URL = ‘https://gitlab.com’  # Change to your GitLab instance URL
PRIVATE_TOKEN = ‘your-gitlab-personal-access-token’  # Replace with your token

```
# Initialize reporter
reporter = GitLabTopicAccessReport(GITLAB_URL, PRIVATE_TOKEN)

# Generate consolidated report
reporter.generate_consolidated_report(
    output_csv='topic_access_report.csv',
    output_json='topic_access_report.json'
)

print("\n✓ All reports generated successfully!")
print("Files created:")
print("  - topic_access_report.csv (Detailed report with one row per project)")
print("  - topic_access_summary.csv (Summary with one row per user)")
print("  - topic_access_report.json (Detailed JSON with group info)")
print("  - topic_access_statistics.txt (Summary statistics)")
```