import { json } from "@remix-run/node";
import { useLoaderData, useFetcher } from "@remix-run/react";
import { PageHeader } from "~/components/PageHeader";
import { AWS } from "~/aws.server";

export const loader = async () => {
  try {
    const qconnect = new AWS.QConnect();
    const knowledgeBases = await qconnect.listKnowledgeBases().promise();
    
    return json({
      title: "Q in Connect",
      description: "Manage Amazon Q in Connect knowledgebases and content",
      knowledgeBases: knowledgeBases.knowledgeBaseSummaries || []
    });
  } catch (error) {
    console.error("Error fetching knowledgebases:", error);
    return json({
      title: "Q in Connect",
      description: "Manage Amazon Q in Connect knowledgebases and content",
      knowledgeBases: [],
      error: "Failed to fetch knowledgebases. Please check your AWS credentials and permissions."
    });
  }
};

export default function QiCPage() {
  const { title, description, knowledgeBases, error } = useLoaderData<typeof loader>();
  const fetcher = useFetcher();

  return (
    <div className="space-y-6">
      <PageHeader title={title} description={description} />
      <div className="px-4 sm:px-6 lg:px-8">
        {error ? (
          <div className="rounded-md bg-red-50 p-4">
            <div className="flex">
              <div className="ml-3">
                <h3 className="text-sm font-medium text-red-800">Error</h3>
                <div className="mt-2 text-sm text-red-700">
                  <p>{error}</p>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="bg-white shadow overflow-hidden sm:rounded-md">
            <ul role="list" className="divide-y divide-gray-200">
              {knowledgeBases.map((kb) => (
                <li key={kb.knowledgeBaseId}>
                  <div className="px-4 py-4 sm:px-6">
                    <div className="flex items-center justify-between">
                      <div className="text-sm font-medium text-indigo-600 truncate">
                        {kb.name}
                      </div>
                      <div className="ml-2 flex-shrink-0 flex">
                        <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
                          Active
                        </span>
                      </div>
                    </div>
                    <div className="mt-2 sm:flex sm:justify-between">
                      <div className="sm:flex">
                        <p className="flex items-center text-sm text-gray-500">
                          {kb.description || 'No description'}
                        </p>
                      </div>
                      <div className="mt-2 flex items-center text-sm text-gray-500 sm:mt-0">
                        <p>
                          Created {new Date(kb.createdDateTime).toLocaleDateString()}
                        </p>
                      </div>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
} 