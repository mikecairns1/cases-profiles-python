import { HomeIcon, UserGroupIcon, FolderIcon, QuestionMarkCircleIcon } from "@heroicons/react/24/outline";

export function Navigation() {
  return (
    <nav>
      <NavigationLink to="/">
        <HomeIcon /> Home
      </NavigationLink>
      <NavigationLink to="/profiles">
        <UserGroupIcon /> Profiles
      </NavigationLink>
      <NavigationLink to="/cases">
        <FolderIcon /> Cases
      </NavigationLink>
      <NavigationLink to="/qic">
        <QuestionMarkCircleIcon /> QiC
      </NavigationLink>
    </nav>
  );
} 