import requests
import csv
import json
from datetime import datetime
from collections import defaultdict

class GitLabProjectTopicReport:
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

def get_root_group_name(self, namespace_path):
    """
    Extract root group name from namespace path
    Example: 'engineering/devops/team-a' -> 'engineering'
    """
    if not namespace_path:
        return 'Personal/No Group'
    
    parts = namespace_path.split('/')
    return parts[0] if parts else 'Personal/No Group'

def get_all_projects(self):
    """Fetch all projects from GitLab"""
    projects = []
    page = 1
    per_page = 100
    
    print("Fetching all GitLab projects...")
    print("-" * 60)
    
    while True:
        url = f'{self.api_base}/projects'
        params = {
            'page': page,
            'per_page': per_page,
            'membership': True,
            'with_shared': True,
            'simple': False  # Get full project details
        }
        
        response = requests.get(url, headers=self.headers, params=params)
        
        if response.status_code != 200:
            print(f"Error fetching projects: {response.status_code} - {response.text}")
            break
        
        data = response.json()
        if not data:
            break
        
        projects.extend(data)
        print(f"  Page {page}: Fetched {len(data)} projects (Total: {len(projects)})")
        page += 1
    
    print(f"\nTotal projects retrieved: {len(projects)}")
    print("-" * 60 + "\n")
    return projects

def generate_project_topic_report(self, output_csv='gitlab_projects_topics.csv',
                                  output_json='gitlab_projects_topics.json'):
    """
    Generate report with all projects, their URLs, root groups, and topics
    Includes projects with empty topics
    """
    
    projects = self.get_all_projects()
    
    # Prepare data structure
    project_data = []
    stats = {
        'total_projects': len(projects),
        'projects_with_topics': 0,
        'projects_without_topics': 0,
        'unique_topics': set(),
        'unique_root_groups': set(),
        'personal_projects': 0
    }
    
    print("Processing project details...")
    for idx, project in enumerate(projects, 1):
        # Extract project information
        project_id = project['id']
        project_name = project['name']
        project_path = project['path']
        project_path_with_namespace = project['path_with_namespace']
        project_web_url = project['web_url']
        project_description = project.get('description', '')
        
        # Get namespace information
        namespace = project.get('namespace', {})
        namespace_kind = namespace.get('kind', 'user')
        namespace_name = namespace.get('name', 'Personal')
        namespace_path = namespace.get('path', '')
        namespace_full_path = namespace.get('full_path', '')
        
        # Determine root group
        if namespace_kind == 'group':
            root_group = self.get_root_group_name(namespace_full_path)
            stats['unique_root_groups'].add(root_group)
        else:
            root_group = 'Personal/No Group'
            stats['personal_projects'] += 1
        
        # Get topics
        topics = project.get('topics', []) or project.get('tag_list', [])
        topics_str = ', '.join(topics) if topics else ''
        
        # Update statistics
        if topics:
            stats['projects_with_topics'] += 1
            stats['unique_topics'].update(topics)
        else:
            stats['projects_without_topics'] += 1
        
        # Store project data
        project_info = {
            'project_id': project_id,
            'project_name': project_name,
            'project_path': project_path,
            'project_full_path': project_path_with_namespace,
            'project_url': project_web_url,
            'project_description': project_description,
            'namespace_kind': namespace_kind,
            'namespace_name': namespace_name,
            'namespace_path': namespace_path,
            'namespace_full_path': namespace_full_path,
            'root_group': root_group,
            'topics': topics,
            'topics_string': topics_str,
            'topic_count': len(topics),
            'has_topics': 'Yes' if topics else 'No'
        }
        
        project_data.append(project_info)
        
        # Progress indicator
        if idx % 50 == 0:
            print(f"  Processed {idx}/{len(projects)} projects...")
    
    print(f"✓ Processed all {len(projects)} projects\n")
    
    # Generate CSV Report
    print("Generating CSV report...")
    with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'Project ID',
            'Project Name',
            'Project Path',
            'Project Full Path',
            'Project URL',
            'Root Group',
            'Namespace Full Path',
            'Namespace Kind',
            'Topics',
            'Topic Count',
            'Has Topics',
            'Description'
        ]
        
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for proj in sorted(project_data, key=lambda x: (x['root_group'], x['project_name'])):
            writer.writerow({
                'Project ID': proj['project_id'],
                'Project Name': proj['project_name'],
                'Project Path': proj['project_path'],
                'Project Full Path': proj['project_full_path'],
                'Project URL': proj['project_url'],
                'Root Group': proj['root_group'],
                'Namespace Full Path': proj['namespace_full_path'],
                'Namespace Kind': proj['namespace_kind'],
                'Topics': proj['topics_string'],
                'Topic Count': proj['topic_count'],
                'Has Topics': proj['has_topics'],
                'Description': proj['project_description']
            })
    
    print(f"✓ CSV report generated: {output_csv}")
    
    # Generate CSV for projects WITHOUT topics
    no_topics_csv = 'gitlab_projects_without_topics.csv'
    print(f"Generating report for projects without topics...")
    with open(no_topics_csv, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'Project ID',
            'Project Name',
            'Project Full Path',
            'Project URL',
            'Root Group',
            'Description'
        ]
        
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for proj in sorted(project_data, key=lambda x: (x['root_group'], x['project_name'])):
            if not proj['topics']:
                writer.writerow({
                    'Project ID': proj['project_id'],
                    'Project Name': proj['project_name'],
                    'Project Full Path': proj['project_full_path'],
                    'Project URL': proj['project_url'],
                    'Root Group': proj['root_group'],
                    'Description': proj['project_description']
                })
    
    print(f"✓ No-topics CSV generated: {no_topics_csv}")
    
    # Generate Topic breakdown CSV
    topic_breakdown_csv = 'gitlab_topics_breakdown.csv'
    print(f"Generating topic breakdown report...")
    
    # Group projects by topic
    topic_projects = defaultdict(list)
    for proj in project_data:
        if proj['topics']:
            for topic in proj['topics']:
                topic_projects[topic].append(proj)
    
    with open(topic_breakdown_csv, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'Topic',
            'Project Count',
            'Root Groups',
            'Projects'
        ]
        
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for topic in sorted(topic_projects.keys()):
            projects_list = topic_projects[topic]
            root_groups = set(p['root_group'] for p in projects_list)
            project_names = ', '.join(sorted([p['project_name'] for p in projects_list]))
            
            writer.writerow({
                'Topic': topic,
                'Project Count': len(projects_list),
                'Root Groups': ', '.join(sorted(root_groups)),
                'Projects': project_names
            })
    
    print(f"✓ Topic breakdown CSV generated: {topic_breakdown_csv}")
    
    # Generate JSON Report
    print("Generating JSON report...")
    json_output = {
        'generated_at': datetime.now().isoformat(),
        'gitlab_url': self.gitlab_url,
        'statistics': {
            'total_projects': stats['total_projects'],
            'projects_with_topics': stats['projects_with_topics'],
            'projects_without_topics': stats['projects_without_topics'],
            'unique_topics_count': len(stats['unique_topics']),
            'unique_root_groups_count': len(stats['unique_root_groups']),
            'personal_projects': stats['personal_projects'],
            'unique_topics': sorted(list(stats['unique_topics'])),
            'unique_root_groups': sorted(list(stats['unique_root_groups']))
        },
        'projects': project_data
    }
    
    with open(output_json, 'w', encoding='utf-8') as f:
        json.dump(json_output, f, indent=2, ensure_ascii=False)
    
    print(f"✓ JSON report generated: {output_json}")
    
    # Generate Summary Report
    summary_file = 'gitlab_projects_summary.txt'
    print(f"Generating summary report...")
    
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write("GITLAB PROJECTS AND TOPICS SUMMARY REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"GitLab URL: {self.gitlab_url}\n")
        f.write("=" * 70 + "\n\n")
        
        f.write("OVERALL STATISTICS:\n")
        f.write("-" * 70 + "\n")
        f.write(f"Total Projects:              {stats['total_projects']}\n")
        f.write(f"Projects with Topics:        {stats['projects_with_topics']} ({stats['projects_with_topics']/stats['total_projects']*100:.1f}%)\n")
        f.write(f"Projects without Topics:     {stats['projects_without_topics']} ({stats['projects_without_topics']/stats['total_projects']*100:.1f}%)\n")
        f.write(f"Unique Topics:               {len(stats['unique_topics'])}\n")
        f.write(f"Unique Root Groups:          {len(stats['unique_root_groups'])}\n")
        f.write(f"Personal Projects:           {stats['personal_projects']}\n\n")
        
        f.write("ROOT GROUPS:\n")
        f.write("-" * 70 + "\n")
        
        # Count projects per root group
        root_group_counts = defaultdict(int)
        for proj in project_data:
            root_group_counts[proj['root_group']] += 1
        
        for root_group in sorted(root_group_counts.keys()):
            count = root_group_counts[root_group]
            f.write(f"  {root_group:<40} {count:>5} projects\n")
        
        f.write("\n")
        f.write("TOPICS:\n")
        f.write("-" * 70 + "\n")
        
        for topic in sorted(stats['unique_topics']):
            count = len(topic_projects[topic])
            f.write(f"  {topic:<40} {count:>5} projects\n")
        
        f.write("\n")
        f.write("TOP 10 ROOT GROUPS BY PROJECT COUNT:\n")
        f.write("-" * 70 + "\n")
        
        sorted_groups = sorted(root_group_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        for idx, (group, count) in enumerate(sorted_groups, 1):
            f.write(f"  {idx:2}. {group:<40} {count:>5} projects\n")
    
    print(f"✓ Summary report generated: {summary_file}")
    
    # Print console summary
    print("\n" + "=" * 70)
    print("SUMMARY:")
    print("=" * 70)
    print(f"Total Projects:           {stats['total_projects']}")
    print(f"Projects with Topics:     {stats['projects_with_topics']} ({stats['projects_with_topics']/stats['total_projects']*100:.1f}%)")
    print(f"Projects without Topics:  {stats['projects_without_topics']} ({stats['projects_without_topics']/stats['total_projects']*100:.1f}%)")
    print(f"Unique Topics:            {len(stats['unique_topics'])}")
    print(f"Unique Root Groups:       {len(stats['unique_root_groups'])}")
    print(f"\nRoot Groups: {', '.join(sorted(stats['unique_root_groups']))}")
    print(f"\nTopics: {', '.join(sorted(stats['unique_topics']))}")
    print("=" * 70 + "\n")
    
    return project_data, stats
```

# Usage Example

if **name** == “**main**”:
# Configuration
GITLAB_URL = ‘https://gitlab.com’  # Change to your GitLab instance URL
PRIVATE_TOKEN = ‘your-gitlab-personal-access-token’  # Replace with your token

```
# Initialize reporter
reporter = GitLabProjectTopicReport(GITLAB_URL, PRIVATE_TOKEN)

# Generate reports
project_data, stats = reporter.generate_project_topic_report(
    output_csv='gitlab_projects_topics.csv',
    output_json='gitlab_projects_topics.json'
)

print("\n✓ All reports generated successfully!")
print("\nFiles created:")
print("  1. gitlab_projects_topics.csv           - All projects with topics and groups")
print("  2. gitlab_projects_without_topics.csv   - Projects missing topics")
print("  3. gitlab_topics_breakdown.csv          - Topic analysis by project count")
print("  4. gitlab_projects_topics.json          - Complete JSON data")
print("  5. gitlab_projects_summary.txt          - Statistical summary")
print("\n" + "=" * 70)
```