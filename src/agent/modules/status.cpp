#include "src/agent/modules/status.h"
#include "src/common/log.h"
#include "src/common/file_utils.h"

#include <valijson/constraints/concrete_constraints.hpp>

#include <fstream>

LOG_DECLARE_NAMESPACE("agent.modules.status");

namespace Cthun {
namespace Agent {
namespace Modules {

Status::Status() {
    module_name = "status";

    valijson::constraints::TypeConstraint json_type_object {
        valijson::constraints::TypeConstraint::kObject
    };

    valijson::Schema input_schema;
    input_schema.addConstraint(json_type_object);

    valijson::Schema output_schema;
    output_schema.addConstraint(json_type_object);

    actions["query"] = Action { input_schema, output_schema };
}

void Status::call_action(std::string action_name, const Json::Value& input,
                            Json::Value& output) {
    LOG_INFO(input.toStyledString());
    LOG_INFO(input["job_id"].asString());

    std::string job_id { input["job_id"].asString() };

    if (!Common::FileUtils::fileExists("/tmp/cthun_agent/" + job_id)) {
        output["error"] = "No job exists for id: " + job_id;
        return;
    }

    Json::Value status { Common::FileUtils::readFileAsJson("/tmp/cthun_agent/" + job_id + "/status") };

    if (status["status"].compare("running") == 0) {
        output["status"] = "Running";
    } else if (status["status"].compare("completed") == 0) {
        output["status"] = status;
        output["response"] = Common::FileUtils::readFileAsJson("/tmp/cthun_agent/" + job_id + "/stdout");
        //output["stderr"] = Common::FileUtils::readFileAsJson("/tmp/cthun_agent/" + job_id + "/stderr");
    } else {
        output["status"] = "Job '" + job_id + "' is in unknown state: " + status["status"].asString();
    }
}

}  // namespace Modules
}  // namespace Agent
}  // namespace Cthun