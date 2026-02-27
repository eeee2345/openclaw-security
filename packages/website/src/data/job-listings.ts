export interface JobListing {
  id: string;
  title: string;
  department: string;
  location: string;
  type: string;
}

export const departments = [
  'All',
  'Engineering',
  'Security Research',
  'Product',
  'Design',
  'Go-To-Market',
];

export const jobListings: JobListing[] = [
  {
    id: 'sr-backend',
    title: 'Senior Backend Engineer',
    department: 'Engineering',
    location: 'Remote',
    type: 'Full-time',
  },
  {
    id: 'ai-ml-researcher',
    title: 'AI/ML Security Researcher',
    department: 'Security Research',
    location: 'Remote',
    type: 'Full-time',
  },
  {
    id: 'fullstack',
    title: 'Full-Stack Engineer',
    department: 'Engineering',
    location: 'Remote',
    type: 'Full-time',
  },
  {
    id: 'secops',
    title: 'Security Operations Engineer',
    department: 'Security Research',
    location: 'Remote',
    type: 'Full-time',
  },
  {
    id: 'product-designer',
    title: 'Product Designer',
    department: 'Design',
    location: 'Remote',
    type: 'Full-time',
  },
  {
    id: 'dev-advocate',
    title: 'Developer Advocate',
    department: 'Go-To-Market',
    location: 'Remote',
    type: 'Full-time',
  },
  {
    id: 'head-marketing',
    title: 'Head of Marketing',
    department: 'Go-To-Market',
    location: 'Remote / Taipei',
    type: 'Full-time',
  },
  {
    id: 'solutions-eng',
    title: 'Solutions Engineer',
    department: 'Go-To-Market',
    location: 'Remote / Taipei',
    type: 'Full-time',
  },
];
