import aws_cdk as core
import aws_cdk.assertions as assertions

from data_federate.data_federate_stack import DataFederateStack

# example tests. To run these tests, uncomment this file along with the example
# resource in data_federate/data_federate_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = DataFederateStack(app, "data-federate")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
